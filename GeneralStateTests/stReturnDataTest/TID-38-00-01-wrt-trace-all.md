> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.dev/ethereum/tests/blob/develop/GeneralStateTests/stReturnDataTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stReturnDataTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case failed

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-38-05 | clearReturnBuffer |
| TID-38-07 | modexp_modsize0_returndatasize |
| TID-38-09 | returndatacopy_after_failing_callcode |
| TID-38-13 | returndatacopy_after_successful_callcode |
| TID-38-28 | returndatasize_after_failing_callcode |
| TID-38-32 | returndatasize_after_successful_callcode |
| TID-38-39 | revertRetDataSize |
| TID-38-40 | subcallReturnMoreThenExpected |

- Hit with error `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS` (ExitCode::38)

| Test ID | Use-Case |
| --- | --- |
| TID-38-16 | returndatacopy_afterFailing_create |
| TID-38-11 | returndatacopy_after_failing_staticcall |
| TID-38-12 | returndatacopy_after_revert_in_staticcall |
| TID-38-14 | returndatacopy_after_successful_delegatecall |
| TID-38-15 | returndatacopy_after_successful_staticcall |
| TID-38-18 | returndatacopy_following_create |
| TID-38-19 | returndatacopy_following_failing_call |
| TID-38-21 | returndatacopy_following_revert_in_create |
| TID-38-22 | returndatacopy_following_successful_create |
| TID-38-23 | returndatacopy_following_too_big_transfer |
| TID-38-24 | returndatacopy_initial |
| TID-38-25 | returndatacopy_initial_256 |
| TID-38-26 | returndatacopy_initial_big_sum |
| TID-38-27 | returndatacopy_overrun |
| TID-38-41 | tooLongReturnDataCopy |


> Execution Trace

```
2023-01-25T06:50:55.214219Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_ecrec_success_empty_then_returndatasize.json", Total Files :: 1
2023-01-25T06:50:55.311631Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:50:55.311846Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:55.311850Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:50:55.311927Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:55.312019Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:50:55.312025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_ecrec_success_empty_then_returndatasize"::Istanbul::0
2023-01-25T06:50:55.312029Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_ecrec_success_empty_then_returndatasize.json"
2023-01-25T06:50:55.312033Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:55.312035Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 36864, value: 0 }
	input:
2023-01-25T06:50:55.685415Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635309,
    events_root: None,
}
2023-01-25T06:50:55.685431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:50:55.685438Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_ecrec_success_empty_then_returndatasize"::Berlin::0
2023-01-25T06:50:55.685441Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_ecrec_success_empty_then_returndatasize.json"
2023-01-25T06:50:55.685446Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:55.685447Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 36864, value: 0 }
	input:
2023-01-25T06:50:55.685569Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635309,
    events_root: None,
}
2023-01-25T06:50:55.685576Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:50:55.685578Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_ecrec_success_empty_then_returndatasize"::London::0
2023-01-25T06:50:55.685580Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_ecrec_success_empty_then_returndatasize.json"
2023-01-25T06:50:55.685584Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:55.685585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 36864, value: 0 }
	input:
2023-01-25T06:50:55.685688Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635309,
    events_root: None,
}
2023-01-25T06:50:55.685694Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:50:55.685696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_ecrec_success_empty_then_returndatasize"::Merge::0
2023-01-25T06:50:55.685698Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_ecrec_success_empty_then_returndatasize.json"
2023-01-25T06:50:55.685701Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:55.685703Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 36864, value: 0 }
	input:
2023-01-25T06:50:55.685802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635309,
    events_root: None,
}
2023-01-25T06:50:55.687130Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.182298ms
2023-01-25T06:50:55.966527Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_outsize_then_create_successful_then_returndatasize.json", Total Files :: 1
2023-01-25T06:50:55.996522Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:50:55.996723Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:55.996727Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:50:55.996778Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:55.996780Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:50:55.996840Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:55.996912Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:50:55.996915Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_outsize_then_create_successful_then_returndatasize"::Istanbul::0
2023-01-25T06:50:55.996918Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_outsize_then_create_successful_then_returndatasize.json"
2023-01-25T06:50:55.996922Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:55.996923Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-25T06:50:56.613243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15831017,
    events_root: None,
}
2023-01-25T06:50:56.613279Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:50:56.613287Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_outsize_then_create_successful_then_returndatasize"::Berlin::0
2023-01-25T06:50:56.613290Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_outsize_then_create_successful_then_returndatasize.json"
2023-01-25T06:50:56.613294Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:56.613295Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 204, 229, 246, 5, 48, 39, 94, 233, 49, 140, 225, 239, 249, 228, 191, 238, 129, 1, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-25T06:50:56.614049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15132845,
    events_root: None,
}
2023-01-25T06:50:56.614070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:50:56.614073Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_outsize_then_create_successful_then_returndatasize"::London::0
2023-01-25T06:50:56.614076Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_outsize_then_create_successful_then_returndatasize.json"
2023-01-25T06:50:56.614079Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:56.614080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 206, 105, 18, 180, 86, 169, 134, 66, 145, 242, 213, 71, 127, 184, 201, 186, 98, 26, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-25T06:50:56.614715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14960743,
    events_root: None,
}
2023-01-25T06:50:56.614736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:50:56.614739Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_outsize_then_create_successful_then_returndatasize"::Merge::0
2023-01-25T06:50:56.614741Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_outsize_then_create_successful_then_returndatasize.json"
2023-01-25T06:50:56.614744Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:56.614746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 146, 186, 46, 153, 226, 84, 67, 25, 239, 102, 183, 123, 143, 110, 42, 204, 247, 6, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-25T06:50:56.615381Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15097996,
    events_root: None,
}
2023-01-25T06:50:56.617125Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:618.885592ms
2023-01-25T06:50:56.902371Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_call_value_fail_then_returndatasize.json", Total Files :: 1
2023-01-25T06:50:56.930943Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:50:56.931137Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:56.931141Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:50:56.931191Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:56.931193Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:50:56.931252Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:56.931322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:50:56.931326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_then_call_value_fail_then_returndatasize"::Istanbul::0
2023-01-25T06:50:56.931329Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_call_value_fail_then_returndatasize.json"
2023-01-25T06:50:56.931332Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:56.931334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:57.284201Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3231115,
    events_root: None,
}
2023-01-25T06:50:57.284225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:50:57.284232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_then_call_value_fail_then_returndatasize"::Berlin::0
2023-01-25T06:50:57.284235Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_call_value_fail_then_returndatasize.json"
2023-01-25T06:50:57.284238Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:57.284239Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:57.284438Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3231115,
    events_root: None,
}
2023-01-25T06:50:57.284448Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:50:57.284450Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_then_call_value_fail_then_returndatasize"::London::0
2023-01-25T06:50:57.284452Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_call_value_fail_then_returndatasize.json"
2023-01-25T06:50:57.284455Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:57.284456Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:57.284676Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3231115,
    events_root: None,
}
2023-01-25T06:50:57.284687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:50:57.284690Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_then_call_value_fail_then_returndatasize"::Merge::0
2023-01-25T06:50:57.284695Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_call_value_fail_then_returndatasize.json"
2023-01-25T06:50:57.284699Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:57.284701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:57.284891Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3231115,
    events_root: None,
}
2023-01-25T06:50:57.286350Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:353.962139ms
2023-01-25T06:50:57.545614Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_create_successful_then_returndatasize.json", Total Files :: 1
2023-01-25T06:50:57.590976Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:50:57.591170Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:57.591174Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:50:57.591225Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:57.591227Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:50:57.591291Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:57.591360Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:50:57.591363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_then_create_successful_then_returndatasize"::Istanbul::0
2023-01-25T06:50:57.591366Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_create_successful_then_returndatasize.json"
2023-01-25T06:50:57.591369Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:57.591371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-25T06:50:58.227307Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15830465,
    events_root: None,
}
2023-01-25T06:50:58.227344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:50:58.227350Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_then_create_successful_then_returndatasize"::Berlin::0
2023-01-25T06:50:58.227354Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_create_successful_then_returndatasize.json"
2023-01-25T06:50:58.227357Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:58.227358Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 204, 229, 246, 5, 48, 39, 94, 233, 49, 140, 225, 239, 249, 228, 191, 238, 129, 1, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-25T06:50:58.228091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15132292,
    events_root: None,
}
2023-01-25T06:50:58.228111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:50:58.228114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_then_create_successful_then_returndatasize"::London::0
2023-01-25T06:50:58.228117Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_create_successful_then_returndatasize.json"
2023-01-25T06:50:58.228119Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:58.228121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 206, 105, 18, 180, 86, 169, 134, 66, 145, 242, 213, 71, 127, 184, 201, 186, 98, 26, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-25T06:50:58.228756Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14960190,
    events_root: None,
}
2023-01-25T06:50:58.228776Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:50:58.228779Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_then_create_successful_then_returndatasize"::Merge::0
2023-01-25T06:50:58.228782Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/call_then_create_successful_then_returndatasize.json"
2023-01-25T06:50:58.228785Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:58.228786Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 146, 186, 46, 153, 226, 84, 67, 25, 239, 102, 183, 123, 143, 110, 42, 204, 247, 6, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-25T06:50:58.229414Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15097443,
    events_root: None,
}
2023-01-25T06:50:58.231004Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:638.465337ms
2023-01-25T06:50:58.491757Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json", Total Files :: 1
2023-01-25T06:50:58.552109Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:50:58.552310Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:58.552313Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:50:58.552369Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:58.552371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:50:58.552432Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:58.552434Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:50:58.552492Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:58.552494Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-25T06:50:58.552552Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:58.552554Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-25T06:50:58.552620Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:58.552623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-25T06:50:58.552683Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:58.552756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:50:58.552760Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::0
2023-01-25T06:50:58.552762Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:58.552765Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:58.552767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 62, 108, 48, 175, 97, 231, 163, 87, 111, 49, 49, 30, 168, 166, 32, 248, 13, 4, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-25T06:50:59.219522Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16232154,
    events_root: None,
}
2023-01-25T06:50:59.219560Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T06:50:59.219568Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::1
2023-01-25T06:50:59.219571Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.219574Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.219576Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [123, 63, 14, 251, 163, 176, 12, 252, 69, 58, 218, 72, 80, 74, 99, 63, 234, 44, 140, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-25T06:50:59.220454Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17379746,
    events_root: None,
}
2023-01-25T06:50:59.220480Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-25T06:50:59.220484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::2
2023-01-25T06:50:59.220487Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.220489Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.220491Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [13, 83, 208, 190, 175, 193, 2, 24, 196, 168, 70, 211, 220, 208, 10, 69, 20, 217, 129, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-25T06:50:59.221214Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16356909,
    events_root: None,
}
2023-01-25T06:50:59.221238Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-25T06:50:59.221242Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::3
2023-01-25T06:50:59.221244Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.221247Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.221248Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [122, 165, 160, 111, 221, 77, 189, 189, 125, 83, 232, 170, 218, 236, 99, 116, 73, 98, 162, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-25T06:50:59.221995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16862950,
    events_root: None,
}
2023-01-25T06:50:59.222017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-25T06:50:59.222020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::4
2023-01-25T06:50:59.222022Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.222025Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.222026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [5, 28, 172, 31, 198, 249, 247, 63, 56, 11, 135, 233, 182, 56, 71, 167, 97, 204, 120, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
2023-01-25T06:50:59.222707Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17006911,
    events_root: None,
}
2023-01-25T06:50:59.222731Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-25T06:50:59.222734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::5
2023-01-25T06:50:59.222736Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.222738Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.222740Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [112, 68, 19, 37, 117, 76, 12, 39, 178, 17, 165, 60, 4, 198, 194, 134, 160, 185, 28, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
2023-01-25T06:50:59.223430Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18235342,
    events_root: None,
}
2023-01-25T06:50:59.223453Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-25T06:50:59.223455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::6
2023-01-25T06:50:59.223458Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.223462Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.223463Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [89, 54, 162, 61, 97, 252, 63, 233, 234, 101, 89, 156, 15, 33, 199, 43, 185, 41, 232, 218, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
2023-01-25T06:50:59.224164Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18234177,
    events_root: None,
}
2023-01-25T06:50:59.224188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-25T06:50:59.224192Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::7
2023-01-25T06:50:59.224194Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.224197Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.224199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [234, 161, 245, 17, 112, 6, 75, 117, 59, 56, 63, 87, 83, 228, 94, 157, 64, 12, 161, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
2023-01-25T06:50:59.224917Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18173407,
    events_root: None,
}
2023-01-25T06:50:59.224941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-25T06:50:59.224944Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::8
2023-01-25T06:50:59.224946Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.224949Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.224951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [203, 233, 34, 156, 178, 187, 198, 57, 51, 114, 35, 61, 243, 100, 252, 23, 47, 143, 210, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 189, 137, 170, 161, 168, 98, 8, 218, 14, 105, 2, 242, 92, 44, 234, 2, 122, 233, 63]) }
2023-01-25T06:50:59.225544Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14674881,
    events_root: None,
}
2023-01-25T06:50:59.225567Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-25T06:50:59.225571Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::9
2023-01-25T06:50:59.225574Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.225578Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.225580Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [178, 118, 217, 229, 17, 27, 93, 93, 16, 171, 155, 225, 41, 115, 220, 234, 51, 24, 245, 143, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 221, 99, 117, 94, 25, 113, 14, 55, 217, 63, 213, 179, 235, 175, 240, 178, 120, 15, 225]) }
2023-01-25T06:50:59.226307Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16486305,
    events_root: None,
}
2023-01-25T06:50:59.226330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-25T06:50:59.226333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::10
2023-01-25T06:50:59.226335Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.226337Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.226339Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [53, 44, 188, 229, 121, 240, 190, 151, 96, 150, 81, 115, 14, 219, 249, 229, 249, 68, 123, 87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
2023-01-25T06:50:59.227011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16196876,
    events_root: None,
}
2023-01-25T06:50:59.227035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-25T06:50:59.227038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::11
2023-01-25T06:50:59.227040Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.227042Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.227044Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [241, 131, 118, 85, 134, 72, 114, 66, 162, 103, 94, 184, 112, 7, 234, 42, 27, 108, 112, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([90, 217, 32, 146, 24, 201, 117, 10, 10, 210, 28, 70, 31, 30, 132, 56, 243, 180, 75, 35]) }
2023-01-25T06:50:59.227777Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18642801,
    events_root: None,
}
2023-01-25T06:50:59.227800Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-25T06:50:59.227803Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::12
2023-01-25T06:50:59.227805Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.227808Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.227809Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [238, 160, 83, 143, 180, 166, 27, 58, 101, 84, 223, 45, 198, 163, 117, 97, 41, 229, 182, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([128, 138, 188, 155, 213, 11, 225, 143, 246, 50, 199, 246, 94, 148, 129, 183, 56, 152, 76, 55]) }
2023-01-25T06:50:59.228526Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17534702,
    events_root: None,
}
2023-01-25T06:50:59.228549Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-25T06:50:59.228552Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::13
2023-01-25T06:50:59.228556Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.228558Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.228560Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [72, 157, 77, 48, 213, 7, 63, 24, 41, 120, 253, 81, 121, 196, 35, 249, 131, 239, 155, 249, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([55, 124, 170, 147, 221, 2, 18, 238, 216, 76, 43, 142, 118, 199, 246, 132, 57, 223, 23, 100]) }
2023-01-25T06:50:59.229270Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18480927,
    events_root: None,
}
2023-01-25T06:50:59.229294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-25T06:50:59.229298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::14
2023-01-25T06:50:59.229300Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.229302Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.229304Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [50, 9, 108, 64, 144, 23, 238, 139, 134, 185, 217, 146, 148, 124, 91, 108, 196, 17, 106, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 234, 181, 15, 37, 193, 240, 156, 211, 60, 172, 98, 156, 55, 186, 0, 159, 236, 160, 247]) }
2023-01-25T06:50:59.230059Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17871898,
    events_root: None,
}
2023-01-25T06:50:59.230082Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-25T06:50:59.230085Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::15
2023-01-25T06:50:59.230087Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.230090Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.230092Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [70, 54, 255, 73, 140, 115, 153, 195, 42, 107, 179, 90, 233, 199, 118, 34, 204, 28, 6, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 18, 209, 255, 80, 109, 220, 136, 239, 83, 214, 196, 45, 184, 19, 227, 137, 201, 135, 105]) }
2023-01-25T06:50:59.230787Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17085762,
    events_root: None,
}
2023-01-25T06:50:59.230809Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-25T06:50:59.230811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::16
2023-01-25T06:50:59.230813Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.230816Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.230818Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [32, 22, 126, 20, 47, 93, 65, 154, 47, 229, 118, 157, 100, 111, 236, 129, 26, 199, 142, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 33, 161, 133, 93, 209, 38, 110, 16, 16, 237, 126, 30, 78, 59, 192, 15, 148, 83, 57]) }
2023-01-25T06:50:59.231490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16369129,
    events_root: None,
}
2023-01-25T06:50:59.231512Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-25T06:50:59.231515Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::17
2023-01-25T06:50:59.231518Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.231521Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.231522Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [78, 199, 229, 139, 107, 189, 153, 235, 33, 145, 194, 17, 244, 156, 121, 244, 103, 227, 191, 211, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([115, 209, 18, 63, 181, 115, 165, 219, 137, 112, 100, 108, 193, 38, 167, 163, 136, 114, 38, 238]) }
2023-01-25T06:50:59.232187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16589429,
    events_root: None,
}
2023-01-25T06:50:59.232210Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-25T06:50:59.232213Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::18
2023-01-25T06:50:59.232216Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.232219Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.232220Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [176, 125, 5, 127, 140, 102, 11, 147, 147, 217, 38, 28, 12, 254, 138, 222, 17, 85, 58, 180, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([164, 19, 188, 157, 123, 198, 227, 16, 99, 7, 112, 55, 126, 183, 242, 167, 190, 31, 240, 147]) }
2023-01-25T06:50:59.232894Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17114865,
    events_root: None,
}
2023-01-25T06:50:59.232917Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-25T06:50:59.232920Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::19
2023-01-25T06:50:59.232923Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.232926Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.232927Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [251, 89, 75, 248, 129, 126, 102, 148, 255, 51, 50, 183, 118, 23, 57, 159, 53, 33, 79, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 113, 131, 83, 213, 98, 3, 231, 134, 49, 131, 92, 170, 242, 84, 90, 74, 151, 72, 246]) }
2023-01-25T06:50:59.233648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18273680,
    events_root: None,
}
2023-01-25T06:50:59.233671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-25T06:50:59.233674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::20
2023-01-25T06:50:59.233677Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.233680Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.233682Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [166, 135, 83, 217, 72, 28, 48, 84, 44, 62, 212, 40, 254, 30, 193, 171, 156, 100, 228, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 182, 218, 235, 33, 11, 225, 5, 136, 185, 130, 124, 42, 168, 16, 11, 169, 12, 214, 166]) }
2023-01-25T06:50:59.234428Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18210894,
    events_root: None,
}
2023-01-25T06:50:59.234451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-25T06:50:59.234454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::21
2023-01-25T06:50:59.234456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.234458Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.234460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [213, 21, 248, 82, 92, 122, 118, 68, 59, 51, 96, 52, 229, 153, 184, 163, 6, 160, 25, 131, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 103, 96, 100, 116, 249, 190, 222, 117, 123, 178, 182, 219, 22, 101, 99, 7, 208, 237, 37]) }
2023-01-25T06:50:59.235175Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18429023,
    events_root: None,
}
2023-01-25T06:50:59.235198Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-25T06:50:59.235201Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::22
2023-01-25T06:50:59.235203Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.235205Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.235207Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [147, 246, 249, 151, 72, 112, 27, 184, 36, 104, 105, 111, 103, 120, 81, 198, 60, 36, 143, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 101, 220, 118, 126, 227, 221, 111, 130, 239, 232, 201, 210, 70, 69, 50, 207, 38, 17, 72]) }
2023-01-25T06:50:59.235790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14927982,
    events_root: None,
}
2023-01-25T06:50:59.235810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-25T06:50:59.235813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::23
2023-01-25T06:50:59.235815Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.235817Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.235818Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [103, 142, 173, 178, 154, 125, 254, 17, 250, 104, 122, 31, 90, 69, 173, 47, 3, 19, 135, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 34, 247, 70, 142, 122, 19, 174, 255, 98, 183, 37, 253, 210, 62, 191, 224, 79, 199, 228]) }
2023-01-25T06:50:59.236517Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16749759,
    events_root: None,
}
2023-01-25T06:50:59.236543Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 24
2023-01-25T06:50:59.236546Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::24
2023-01-25T06:50:59.236548Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.236551Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.236552Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [244, 174, 57, 228, 235, 75, 84, 205, 182, 182, 183, 96, 218, 85, 192, 190, 62, 51, 102, 157, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 200, 128, 32, 100, 47, 163, 168, 222, 154, 90, 196, 49, 165, 55, 116, 4, 152, 177, 42]) }
2023-01-25T06:50:59.237299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17476451,
    events_root: None,
}
2023-01-25T06:50:59.237327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 25
2023-01-25T06:50:59.237331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::25
2023-01-25T06:50:59.237333Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.237336Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.237338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 43, 69, 132, 72, 212, 28, 181, 192, 70, 226, 96, 218, 89, 102, 33, 115, 184, 139, 134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([39, 202, 0, 61, 220, 84, 98, 79, 206, 62, 176, 253, 44, 186, 245, 199, 23, 163, 253, 50]) }
2023-01-25T06:50:59.238156Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18285011,
    events_root: None,
}
2023-01-25T06:50:59.238181Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 26
2023-01-25T06:50:59.238185Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::26
2023-01-25T06:50:59.238187Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.238190Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.238192Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [23, 66, 176, 7, 95, 219, 241, 208, 166, 143, 237, 165, 229, 24, 180, 36, 241, 63, 175, 222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([192, 88, 99, 161, 23, 254, 175, 39, 213, 169, 153, 253, 197, 254, 95, 117, 145, 246, 7, 95]) }
2023-01-25T06:50:59.238891Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18247845,
    events_root: None,
}
2023-01-25T06:50:59.238915Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 27
2023-01-25T06:50:59.238918Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::27
2023-01-25T06:50:59.238920Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.238923Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.238924Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 111, 243, 139, 83, 5, 223, 31, 162, 134, 255, 93, 125, 234, 13, 237, 175, 229, 43, 246, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 33, 187, 115, 222, 53, 224, 244, 47, 32, 70, 11, 226, 18, 129, 166, 126, 239, 230, 44]) }
2023-01-25T06:50:59.239626Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18358447,
    events_root: None,
}
2023-01-25T06:50:59.239649Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 28
2023-01-25T06:50:59.239652Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::28
2023-01-25T06:50:59.239654Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.239657Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.239659Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.240005Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7315688,
    events_root: None,
}
2023-01-25T06:50:59.240021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 29
2023-01-25T06:50:59.240023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::29
2023-01-25T06:50:59.240026Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.240028Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.240030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.240369Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6233428,
    events_root: None,
}
2023-01-25T06:50:59.240384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 30
2023-01-25T06:50:59.240386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::30
2023-01-25T06:50:59.240389Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.240391Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.240392Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.240746Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7616198,
    events_root: None,
}
2023-01-25T06:50:59.240758Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 31
2023-01-25T06:50:59.240761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::31
2023-01-25T06:50:59.240763Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.240766Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.240767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.241098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6696807,
    events_root: None,
}
2023-01-25T06:50:59.241110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 32
2023-01-25T06:50:59.241113Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::32
2023-01-25T06:50:59.241115Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.241117Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.241120Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.241455Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6712569,
    events_root: None,
}
2023-01-25T06:50:59.241468Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 33
2023-01-25T06:50:59.241472Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::33
2023-01-25T06:50:59.241475Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.241478Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.241480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.241865Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6714156,
    events_root: None,
}
2023-01-25T06:50:59.241878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 34
2023-01-25T06:50:59.241881Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::34
2023-01-25T06:50:59.241883Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.241886Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.241887Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.242224Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6801691,
    events_root: None,
}
2023-01-25T06:50:59.242236Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 35
2023-01-25T06:50:59.242240Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::35
2023-01-25T06:50:59.242242Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.242245Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.242246Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.242586Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6801719,
    events_root: None,
}
2023-01-25T06:50:59.242599Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 36
2023-01-25T06:50:59.242601Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::36
2023-01-25T06:50:59.242605Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.242607Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.242609Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.242867Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5512805,
    events_root: None,
}
2023-01-25T06:50:59.242878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 37
2023-01-25T06:50:59.242881Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::37
2023-01-25T06:50:59.242883Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.242886Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.242887Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.243229Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7446493,
    events_root: None,
}
2023-01-25T06:50:59.243242Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 38
2023-01-25T06:50:59.243245Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::38
2023-01-25T06:50:59.243247Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.243249Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.243251Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.243595Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6748624,
    events_root: None,
}
2023-01-25T06:50:59.243608Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 39
2023-01-25T06:50:59.243611Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::39
2023-01-25T06:50:59.243613Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.243615Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.243617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.243959Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6750211,
    events_root: None,
}
2023-01-25T06:50:59.243972Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 40
2023-01-25T06:50:59.243975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::40
2023-01-25T06:50:59.243977Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.243980Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.243981Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.244326Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6836209,
    events_root: None,
}
2023-01-25T06:50:59.244340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 41
2023-01-25T06:50:59.244343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::41
2023-01-25T06:50:59.244345Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.244350Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.244352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.244753Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6836237,
    events_root: None,
}
2023-01-25T06:50:59.244766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 42
2023-01-25T06:50:59.244769Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::42
2023-01-25T06:50:59.244771Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.244773Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.244775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.244885Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.244890Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.244902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 43
2023-01-25T06:50:59.244904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::43
2023-01-25T06:50:59.244906Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.244909Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.244910Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.245009Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.245014Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.245024Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 44
2023-01-25T06:50:59.245026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::44
2023-01-25T06:50:59.245028Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.245031Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.245032Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.245130Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.245135Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.245144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 45
2023-01-25T06:50:59.245146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::45
2023-01-25T06:50:59.245148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.245151Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.245152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.245251Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.245256Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.245265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 46
2023-01-25T06:50:59.245267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::46
2023-01-25T06:50:59.245269Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.245271Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.245272Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.245374Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.245379Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.245388Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 47
2023-01-25T06:50:59.245391Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::47
2023-01-25T06:50:59.245393Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.245397Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.245399Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.245528Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.245536Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.245548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 48
2023-01-25T06:50:59.245551Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::48
2023-01-25T06:50:59.245554Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.245557Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.245559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.245668Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.245672Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.245683Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 49
2023-01-25T06:50:59.245685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::49
2023-01-25T06:50:59.245687Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.245689Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.245691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.245789Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.245794Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.245803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 50
2023-01-25T06:50:59.245805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::50
2023-01-25T06:50:59.245807Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.245809Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.245811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.245911Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.245916Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.245925Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 51
2023-01-25T06:50:59.245927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::51
2023-01-25T06:50:59.245929Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.245931Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.245933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.246030Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.246034Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.246044Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 52
2023-01-25T06:50:59.246046Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::52
2023-01-25T06:50:59.246049Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.246052Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.246054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.246183Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.246190Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.246203Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 53
2023-01-25T06:50:59.246206Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::53
2023-01-25T06:50:59.246208Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.246212Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.246214Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.246321Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.246326Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.246336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 54
2023-01-25T06:50:59.246338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::54
2023-01-25T06:50:59.246340Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.246343Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.246344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.246447Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.246452Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.246460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 55
2023-01-25T06:50:59.246462Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::55
2023-01-25T06:50:59.246464Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.246467Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.246468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.246567Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.246572Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.246580Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 56
2023-01-25T06:50:59.246582Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::56
2023-01-25T06:50:59.246584Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.246586Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.246588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.247025Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9189087,
    events_root: None,
}
2023-01-25T06:50:59.247042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 57
2023-01-25T06:50:59.247045Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::57
2023-01-25T06:50:59.247047Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.247049Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.247051Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.247491Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9225371,
    events_root: None,
}
2023-01-25T06:50:59.247510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 58
2023-01-25T06:50:59.247513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::58
2023-01-25T06:50:59.247515Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.247518Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.247520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.248038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9178076,
    events_root: None,
}
2023-01-25T06:50:59.248060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 59
2023-01-25T06:50:59.248064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::59
2023-01-25T06:50:59.248068Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.248072Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.248074Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.248600Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9180764,
    events_root: None,
}
2023-01-25T06:50:59.248619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 60
2023-01-25T06:50:59.248622Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::60
2023-01-25T06:50:59.248624Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.248626Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.248628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.249071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9193402,
    events_root: None,
}
2023-01-25T06:50:59.249088Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 61
2023-01-25T06:50:59.249092Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::61
2023-01-25T06:50:59.249094Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.249097Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.249099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.249531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9195000,
    events_root: None,
}
2023-01-25T06:50:59.249549Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 62
2023-01-25T06:50:59.249552Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::62
2023-01-25T06:50:59.249555Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.249558Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.249559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.250000Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9282523,
    events_root: None,
}
2023-01-25T06:50:59.250018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 63
2023-01-25T06:50:59.250021Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::63
2023-01-25T06:50:59.250023Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.250025Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.250027Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.250469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9282552,
    events_root: None,
}
2023-01-25T06:50:59.250486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 64
2023-01-25T06:50:59.250489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::64
2023-01-25T06:50:59.250491Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.250494Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.250495Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.250826Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6614560,
    events_root: None,
}
2023-01-25T06:50:59.250838Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 65
2023-01-25T06:50:59.250840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::65
2023-01-25T06:50:59.250842Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.250845Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.250846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.251296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9221394,
    events_root: None,
}
2023-01-25T06:50:59.251316Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 66
2023-01-25T06:50:59.251318Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::66
2023-01-25T06:50:59.251321Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.251323Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.251324Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.251834Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9229457,
    events_root: None,
}
2023-01-25T06:50:59.251852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 67
2023-01-25T06:50:59.251855Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::67
2023-01-25T06:50:59.251857Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.251859Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.251861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.252325Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9231054,
    events_root: None,
}
2023-01-25T06:50:59.252344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 68
2023-01-25T06:50:59.252347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::68
2023-01-25T06:50:59.252349Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.252351Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.252353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.252798Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9317042,
    events_root: None,
}
2023-01-25T06:50:59.252815Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 69
2023-01-25T06:50:59.252819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::69
2023-01-25T06:50:59.252821Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.252823Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.252825Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.253268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9317070,
    events_root: None,
}
2023-01-25T06:50:59.253285Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 70
2023-01-25T06:50:59.253289Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::70
2023-01-25T06:50:59.253291Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.253293Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.253295Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.253604Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5765583,
    events_root: None,
}
2023-01-25T06:50:59.253617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 71
2023-01-25T06:50:59.253619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::71
2023-01-25T06:50:59.253621Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.253624Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.253625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.253936Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5827923,
    events_root: None,
}
2023-01-25T06:50:59.253949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 72
2023-01-25T06:50:59.253952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::72
2023-01-25T06:50:59.253954Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.253956Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.253958Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.254265Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5760519,
    events_root: None,
}
2023-01-25T06:50:59.254276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 73
2023-01-25T06:50:59.254279Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::73
2023-01-25T06:50:59.254281Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.254284Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.254285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.254619Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4845992,
    events_root: None,
}
2023-01-25T06:50:59.254634Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 74
2023-01-25T06:50:59.254637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::74
2023-01-25T06:50:59.254640Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.254643Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.254645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.254984Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4861671,
    events_root: None,
}
2023-01-25T06:50:59.254999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 75
2023-01-25T06:50:59.255003Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::75
2023-01-25T06:50:59.255006Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.255009Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.255011Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.255373Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4861947,
    events_root: None,
}
2023-01-25T06:50:59.255387Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 76
2023-01-25T06:50:59.255393Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::76
2023-01-25T06:50:59.255395Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.255399Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.255400Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.255785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4949470,
    events_root: None,
}
2023-01-25T06:50:59.255797Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 77
2023-01-25T06:50:59.255800Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::77
2023-01-25T06:50:59.255802Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.255804Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.255806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.256135Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4949499,
    events_root: None,
}
2023-01-25T06:50:59.256149Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 78
2023-01-25T06:50:59.256152Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::78
2023-01-25T06:50:59.256155Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.256158Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.256160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.256426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4257566,
    events_root: None,
}
2023-01-25T06:50:59.256437Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 79
2023-01-25T06:50:59.256440Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::79
2023-01-25T06:50:59.256442Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.256444Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.256446Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.256756Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5826514,
    events_root: None,
}
2023-01-25T06:50:59.256768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 80
2023-01-25T06:50:59.256771Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::80
2023-01-25T06:50:59.256773Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.256775Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.256777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.257073Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4920726,
    events_root: None,
}
2023-01-25T06:50:59.257085Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 81
2023-01-25T06:50:59.257088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::81
2023-01-25T06:50:59.257092Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.257094Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.257096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.257390Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4921002,
    events_root: None,
}
2023-01-25T06:50:59.257402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 82
2023-01-25T06:50:59.257405Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::82
2023-01-25T06:50:59.257407Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.257409Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.257411Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.257735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5006990,
    events_root: None,
}
2023-01-25T06:50:59.257747Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 83
2023-01-25T06:50:59.257751Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::83
2023-01-25T06:50:59.257753Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.257755Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.257757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.258084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5007018,
    events_root: None,
}
2023-01-25T06:50:59.258096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 84
2023-01-25T06:50:59.258099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::84
2023-01-25T06:50:59.258100Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.258103Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.258104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.258439Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5750494,
    events_root: None,
}
2023-01-25T06:50:59.258452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 85
2023-01-25T06:50:59.258455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::85
2023-01-25T06:50:59.258457Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.258459Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.258461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.258769Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5789602,
    events_root: None,
}
2023-01-25T06:50:59.258782Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 86
2023-01-25T06:50:59.258786Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::86
2023-01-25T06:50:59.258788Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.258790Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.258792Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.259092Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5744666,
    events_root: None,
}
2023-01-25T06:50:59.259104Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 87
2023-01-25T06:50:59.259107Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::87
2023-01-25T06:50:59.259109Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.259112Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.259113Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.259399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4827803,
    events_root: None,
}
2023-01-25T06:50:59.259411Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 88
2023-01-25T06:50:59.259413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::88
2023-01-25T06:50:59.259415Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.259418Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.259419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.259706Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4844770,
    events_root: None,
}
2023-01-25T06:50:59.259718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 89
2023-01-25T06:50:59.259721Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::89
2023-01-25T06:50:59.259723Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.259727Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.259728Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.260038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4845046,
    events_root: None,
}
2023-01-25T06:50:59.260050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 90
2023-01-25T06:50:59.260053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::90
2023-01-25T06:50:59.260055Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.260058Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.260059Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.260368Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4932569,
    events_root: None,
}
2023-01-25T06:50:59.260380Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 91
2023-01-25T06:50:59.260382Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::91
2023-01-25T06:50:59.260386Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.260389Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.260390Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.260687Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4932598,
    events_root: None,
}
2023-01-25T06:50:59.260699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 92
2023-01-25T06:50:59.260701Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::92
2023-01-25T06:50:59.260703Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.260706Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.260707Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.260935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4218189,
    events_root: None,
}
2023-01-25T06:50:59.260946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 93
2023-01-25T06:50:59.260948Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::93
2023-01-25T06:50:59.260950Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.260953Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.260955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.261258Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5787281,
    events_root: None,
}
2023-01-25T06:50:59.261272Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 94
2023-01-25T06:50:59.261274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::94
2023-01-25T06:50:59.261277Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.261279Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.261280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.261577Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4880825,
    events_root: None,
}
2023-01-25T06:50:59.261589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 95
2023-01-25T06:50:59.261591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::95
2023-01-25T06:50:59.261593Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.261595Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.261597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.261887Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4881100,
    events_root: None,
}
2023-01-25T06:50:59.261899Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 96
2023-01-25T06:50:59.261901Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::96
2023-01-25T06:50:59.261903Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.261906Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.261907Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.262204Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4967088,
    events_root: None,
}
2023-01-25T06:50:59.262218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 97
2023-01-25T06:50:59.262220Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::97
2023-01-25T06:50:59.262223Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.262225Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.262226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.262526Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4967116,
    events_root: None,
}
2023-01-25T06:50:59.262538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 98
2023-01-25T06:50:59.262540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::98
2023-01-25T06:50:59.262543Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.262545Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.262546Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.262654Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.262659Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.262669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 99
2023-01-25T06:50:59.262672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::99
2023-01-25T06:50:59.262673Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.262676Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.262677Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.262782Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.262787Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.262796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 100
2023-01-25T06:50:59.262799Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::100
2023-01-25T06:50:59.262801Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.262803Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.262805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.262905Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.262910Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.262918Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 101
2023-01-25T06:50:59.262921Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::101
2023-01-25T06:50:59.262923Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.262925Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.262927Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.263025Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.263029Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.263038Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 102
2023-01-25T06:50:59.263040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::102
2023-01-25T06:50:59.263042Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.263044Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.263046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.263144Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.263148Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.263156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 103
2023-01-25T06:50:59.263159Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::103
2023-01-25T06:50:59.263161Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.263164Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.263166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.263265Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.263269Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.263277Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 104
2023-01-25T06:50:59.263280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::104
2023-01-25T06:50:59.263281Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.263283Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.263285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.263395Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.263400Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.263409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 105
2023-01-25T06:50:59.263411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::105
2023-01-25T06:50:59.263413Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.263415Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.263417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.263518Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.263523Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.263532Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 106
2023-01-25T06:50:59.263535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::106
2023-01-25T06:50:59.263536Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.263539Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.263540Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.263639Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.263643Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.263652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 107
2023-01-25T06:50:59.263654Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::107
2023-01-25T06:50:59.263656Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.263658Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.263660Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.263758Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.263762Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.263770Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 108
2023-01-25T06:50:59.263773Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::108
2023-01-25T06:50:59.263775Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.263777Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.263778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.263877Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.263881Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.263889Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 109
2023-01-25T06:50:59.263892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::109
2023-01-25T06:50:59.263899Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.263902Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.263903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.264031Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.264037Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.264051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 110
2023-01-25T06:50:59.264054Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::110
2023-01-25T06:50:59.264057Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.264060Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.264062Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.264175Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.264180Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.264190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 111
2023-01-25T06:50:59.264193Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::111
2023-01-25T06:50:59.264194Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.264197Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.264198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.264301Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.264306Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.264314Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 112
2023-01-25T06:50:59.264316Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::112
2023-01-25T06:50:59.264318Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.264321Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.264322Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.264707Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6693921,
    events_root: None,
}
2023-01-25T06:50:59.264723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 113
2023-01-25T06:50:59.264726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::113
2023-01-25T06:50:59.264728Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.264731Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.264732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.265108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6733769,
    events_root: None,
}
2023-01-25T06:50:59.265124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 114
2023-01-25T06:50:59.265127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::114
2023-01-25T06:50:59.265129Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.265131Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.265133Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.265521Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6687569,
    events_root: None,
}
2023-01-25T06:50:59.265537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 115
2023-01-25T06:50:59.265539Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::115
2023-01-25T06:50:59.265542Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.265544Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.265545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.265905Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5771230,
    events_root: None,
}
2023-01-25T06:50:59.265919Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 116
2023-01-25T06:50:59.265922Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::116
2023-01-25T06:50:59.265925Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.265929Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.265931Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.266341Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5788197,
    events_root: None,
}
2023-01-25T06:50:59.266354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 117
2023-01-25T06:50:59.266356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::117
2023-01-25T06:50:59.266359Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.266362Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.266363Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.266728Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5788473,
    events_root: None,
}
2023-01-25T06:50:59.266741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 118
2023-01-25T06:50:59.266743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::118
2023-01-25T06:50:59.266746Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.266750Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.266751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.267113Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5875996,
    events_root: None,
}
2023-01-25T06:50:59.267127Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 119
2023-01-25T06:50:59.267130Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::119
2023-01-25T06:50:59.267132Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.267135Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.267136Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.267500Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5876025,
    events_root: None,
}
2023-01-25T06:50:59.267512Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 120
2023-01-25T06:50:59.267515Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::120
2023-01-25T06:50:59.267517Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.267519Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.267521Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.267819Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5162487,
    events_root: None,
}
2023-01-25T06:50:59.267830Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 121
2023-01-25T06:50:59.267833Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::121
2023-01-25T06:50:59.267835Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.267838Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.267839Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.268225Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6731071,
    events_root: None,
}
2023-01-25T06:50:59.268241Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 122
2023-01-25T06:50:59.268244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::122
2023-01-25T06:50:59.268246Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.268248Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.268250Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.268613Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5824759,
    events_root: None,
}
2023-01-25T06:50:59.268625Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 123
2023-01-25T06:50:59.268629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::123
2023-01-25T06:50:59.268631Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.268633Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.268635Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.268999Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5825035,
    events_root: None,
}
2023-01-25T06:50:59.269013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 124
2023-01-25T06:50:59.269018Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::124
2023-01-25T06:50:59.269021Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.269025Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.269027Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.269457Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5911023,
    events_root: None,
}
2023-01-25T06:50:59.269470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 125
2023-01-25T06:50:59.269472Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::125
2023-01-25T06:50:59.269475Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.269477Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.269478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.269848Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5911051,
    events_root: None,
}
2023-01-25T06:50:59.269860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 126
2023-01-25T06:50:59.269863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::126
2023-01-25T06:50:59.269865Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.269868Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.269869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.270167Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5725080,
    events_root: None,
}
2023-01-25T06:50:59.270178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 127
2023-01-25T06:50:59.270181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::127
2023-01-25T06:50:59.270183Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.270185Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.270188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.270498Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5786681,
    events_root: None,
}
2023-01-25T06:50:59.270510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 128
2023-01-25T06:50:59.270513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::128
2023-01-25T06:50:59.270515Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.270518Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.270520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.270817Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5719253,
    events_root: None,
}
2023-01-25T06:50:59.270829Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 129
2023-01-25T06:50:59.270831Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::129
2023-01-25T06:50:59.270834Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.270836Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.270837Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.271116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4802390,
    events_root: None,
}
2023-01-25T06:50:59.271127Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 130
2023-01-25T06:50:59.271130Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::130
2023-01-25T06:50:59.271132Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.271135Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.271136Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.271416Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4819356,
    events_root: None,
}
2023-01-25T06:50:59.271428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 131
2023-01-25T06:50:59.271431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::131
2023-01-25T06:50:59.271435Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.271437Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.271439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.271718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4819632,
    events_root: None,
}
2023-01-25T06:50:59.271730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 132
2023-01-25T06:50:59.271733Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::132
2023-01-25T06:50:59.271736Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.271740Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.271742Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.272100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4907156,
    events_root: None,
}
2023-01-25T06:50:59.272115Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 133
2023-01-25T06:50:59.272119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::133
2023-01-25T06:50:59.272121Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.272125Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.272126Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.272489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4907184,
    events_root: None,
}
2023-01-25T06:50:59.272504Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 134
2023-01-25T06:50:59.272508Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::134
2023-01-25T06:50:59.272511Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.272515Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.272517Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.272802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4215268,
    events_root: None,
}
2023-01-25T06:50:59.272814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 135
2023-01-25T06:50:59.272818Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::135
2023-01-25T06:50:59.272820Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.272825Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.272827Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.273254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5784360,
    events_root: None,
}
2023-01-25T06:50:59.273272Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 136
2023-01-25T06:50:59.273276Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::136
2023-01-25T06:50:59.273278Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.273282Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.273284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.273612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4877904,
    events_root: None,
}
2023-01-25T06:50:59.273628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 137
2023-01-25T06:50:59.273631Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::137
2023-01-25T06:50:59.273634Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.273637Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.273639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.273957Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4878179,
    events_root: None,
}
2023-01-25T06:50:59.273969Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 138
2023-01-25T06:50:59.273972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::138
2023-01-25T06:50:59.273974Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.273976Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.273978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.274276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4964167,
    events_root: None,
}
2023-01-25T06:50:59.274289Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 139
2023-01-25T06:50:59.274291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::139
2023-01-25T06:50:59.274293Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.274296Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.274298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.274594Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4964195,
    events_root: None,
}
2023-01-25T06:50:59.274606Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 140
2023-01-25T06:50:59.274609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::140
2023-01-25T06:50:59.274611Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.274614Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.274615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [122, 197, 218, 92, 5, 88, 91, 190, 215, 219, 103, 242, 73, 203, 33, 159, 79, 185, 88, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([229, 134, 218, 28, 173, 120, 102, 217, 86, 17, 87, 148, 11, 132, 141, 172, 158, 89, 43, 245]) }
2023-01-25T06:50:59.275541Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16700877,
    events_root: None,
}
2023-01-25T06:50:59.275563Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 141
2023-01-25T06:50:59.275566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::141
2023-01-25T06:50:59.275568Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.275571Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.275573Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [45, 57, 187, 8, 34, 109, 230, 150, 246, 189, 22, 114, 93, 73, 193, 151, 185, 96, 244, 134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([223, 202, 140, 233, 184, 139, 245, 92, 60, 253, 237, 185, 78, 222, 238, 205, 254, 61, 116, 112]) }
2023-01-25T06:50:59.276255Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15887564,
    events_root: None,
}
2023-01-25T06:50:59.276277Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 142
2023-01-25T06:50:59.276280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::142
2023-01-25T06:50:59.276282Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.276285Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.276286Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [236, 161, 28, 62, 180, 171, 113, 135, 137, 236, 66, 253, 59, 178, 112, 119, 233, 56, 7, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([27, 47, 20, 62, 115, 89, 64, 100, 228, 180, 154, 197, 75, 89, 74, 3, 65, 136, 122, 18]) }
2023-01-25T06:50:59.276938Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15647413,
    events_root: None,
}
2023-01-25T06:50:59.276959Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 143
2023-01-25T06:50:59.276962Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::143
2023-01-25T06:50:59.276964Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.276966Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.276968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [240, 177, 113, 125, 133, 95, 107, 195, 121, 146, 240, 197, 90, 207, 141, 30, 210, 151, 69, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([149, 71, 225, 67, 173, 140, 14, 147, 102, 27, 208, 141, 97, 205, 181, 63, 253, 204, 193, 100]) }
2023-01-25T06:50:59.277611Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15521440,
    events_root: None,
}
2023-01-25T06:50:59.277631Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 144
2023-01-25T06:50:59.277634Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::144
2023-01-25T06:50:59.277636Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.277638Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.277640Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [140, 64, 248, 100, 136, 236, 250, 251, 92, 104, 248, 49, 70, 113, 111, 194, 119, 173, 33, 224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([137, 145, 54, 83, 246, 51, 78, 58, 91, 216, 106, 48, 128, 183, 231, 127, 217, 76, 111, 78]) }
2023-01-25T06:50:59.278269Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14509482,
    events_root: None,
}
2023-01-25T06:50:59.278289Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 145
2023-01-25T06:50:59.278292Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::145
2023-01-25T06:50:59.278294Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.278297Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.278299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [79, 57, 117, 186, 225, 31, 71, 10, 71, 123, 136, 128, 89, 9, 200, 64, 74, 151, 13, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([159, 71, 60, 185, 123, 210, 99, 236, 135, 165, 57, 125, 84, 113, 104, 125, 111, 150, 82, 231]) }
2023-01-25T06:50:59.279006Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15889568,
    events_root: None,
}
2023-01-25T06:50:59.279026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 146
2023-01-25T06:50:59.279029Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::146
2023-01-25T06:50:59.279032Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.279034Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.279036Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [36, 185, 43, 184, 241, 197, 150, 5, 227, 97, 124, 125, 74, 112, 168, 252, 182, 149, 79, 205, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([9, 224, 232, 168, 153, 181, 62, 58, 189, 119, 63, 170, 224, 170, 186, 134, 128, 166, 153, 2]) }
2023-01-25T06:50:59.279698Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16140907,
    events_root: None,
}
2023-01-25T06:50:59.279719Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 147
2023-01-25T06:50:59.279722Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::147
2023-01-25T06:50:59.279724Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.279727Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.279728Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [149, 135, 152, 219, 39, 115, 41, 85, 239, 255, 176, 175, 201, 245, 10, 27, 176, 19, 113, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([72, 105, 66, 48, 74, 19, 182, 9, 127, 234, 99, 15, 143, 107, 125, 55, 183, 169, 1, 75]) }
2023-01-25T06:50:59.280410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16636121,
    events_root: None,
}
2023-01-25T06:50:59.280430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 148
2023-01-25T06:50:59.280434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::148
2023-01-25T06:50:59.280437Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.280439Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.280440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 171, 115, 82, 227, 18, 139, 216, 111, 223, 93, 156, 13, 199, 145, 75, 187, 6, 185, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 13, 34, 169, 194, 222, 156, 216, 136, 151, 149, 175, 128, 183, 62, 242, 162, 66, 247, 154]) }
2023-01-25T06:50:59.280992Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13401956,
    events_root: None,
}
2023-01-25T06:50:59.281009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 149
2023-01-25T06:50:59.281011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::149
2023-01-25T06:50:59.281014Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.281018Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.281020Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [105, 84, 46, 58, 129, 168, 208, 17, 134, 176, 52, 53, 12, 237, 133, 115, 170, 29, 22, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([131, 115, 166, 173, 188, 201, 114, 218, 180, 15, 32, 132, 97, 59, 168, 72, 199, 135, 26, 237]) }
2023-01-25T06:50:59.281658Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15264958,
    events_root: None,
}
2023-01-25T06:50:59.281680Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 150
2023-01-25T06:50:59.281683Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::150
2023-01-25T06:50:59.281685Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.281688Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.281690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [81, 62, 218, 192, 104, 205, 92, 33, 169, 107, 21, 76, 14, 200, 50, 130, 212, 182, 202, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([18, 39, 234, 47, 187, 115, 16, 236, 114, 133, 188, 67, 197, 218, 58, 244, 8, 111, 45, 93]) }
2023-01-25T06:50:59.282330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15286327,
    events_root: None,
}
2023-01-25T06:50:59.282352Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 151
2023-01-25T06:50:59.282355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::151
2023-01-25T06:50:59.282358Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.282361Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.282362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [220, 193, 18, 60, 151, 132, 153, 172, 79, 154, 163, 134, 75, 111, 141, 31, 182, 250, 69, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([196, 252, 58, 192, 43, 102, 19, 227, 208, 48, 84, 217, 49, 54, 72, 20, 86, 249, 108, 199]) }
2023-01-25T06:50:59.283076Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16555408,
    events_root: None,
}
2023-01-25T06:50:59.283098Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 152
2023-01-25T06:50:59.283100Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::152
2023-01-25T06:50:59.283102Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.283105Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.283106Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [4, 164, 10, 221, 0, 135, 41, 103, 106, 2, 45, 240, 118, 136, 90, 92, 92, 140, 75, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([104, 100, 146, 14, 168, 38, 124, 198, 79, 189, 132, 64, 2, 229, 247, 115, 204, 163, 78, 56]) }
2023-01-25T06:50:59.283788Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16743935,
    events_root: None,
}
2023-01-25T06:50:59.283810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 153
2023-01-25T06:50:59.283812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::153
2023-01-25T06:50:59.283815Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.283817Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.283819Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [25, 236, 15, 167, 249, 230, 98, 26, 64, 23, 178, 63, 27, 27, 118, 213, 175, 202, 223, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([248, 236, 36, 139, 209, 50, 63, 77, 176, 13, 235, 83, 117, 214, 72, 106, 36, 231, 224, 83]) }
2023-01-25T06:50:59.284514Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16972463,
    events_root: None,
}
2023-01-25T06:50:59.284536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 154
2023-01-25T06:50:59.284540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::154
2023-01-25T06:50:59.284542Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.284545Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.284546Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [25, 113, 216, 77, 174, 110, 112, 65, 17, 241, 34, 169, 219, 145, 104, 31, 248, 196, 45, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([36, 188, 161, 83, 225, 149, 170, 173, 187, 199, 21, 89, 135, 233, 104, 124, 133, 104, 36, 47]) }
2023-01-25T06:50:59.285273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16475693,
    events_root: None,
}
2023-01-25T06:50:59.285295Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 155
2023-01-25T06:50:59.285298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::155
2023-01-25T06:50:59.285300Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.285303Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.285304Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [102, 136, 233, 182, 19, 57, 244, 216, 191, 241, 181, 246, 26, 60, 139, 71, 6, 173, 253, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([66, 65, 152, 213, 159, 82, 223, 248, 171, 98, 8, 190, 84, 85, 124, 203, 165, 140, 121, 165]) }
2023-01-25T06:50:59.286123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15899211,
    events_root: None,
}
2023-01-25T06:50:59.286150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 156
2023-01-25T06:50:59.286154Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::156
2023-01-25T06:50:59.286156Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.286158Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.286160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [23, 174, 67, 191, 185, 130, 26, 246, 195, 208, 54, 109, 208, 253, 244, 209, 165, 46, 35, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([245, 222, 198, 130, 175, 92, 183, 6, 115, 219, 17, 82, 10, 189, 100, 94, 176, 56, 53, 204]) }
2023-01-25T06:50:59.286836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15495428,
    events_root: None,
}
2023-01-25T06:50:59.286859Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 157
2023-01-25T06:50:59.286862Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::157
2023-01-25T06:50:59.286865Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.286869Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.286872Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [234, 110, 16, 153, 38, 6, 218, 156, 122, 169, 121, 26, 254, 151, 59, 149, 82, 243, 17, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([47, 143, 208, 29, 244, 71, 123, 233, 135, 174, 142, 22, 199, 133, 150, 66, 191, 126, 245, 105]) }
2023-01-25T06:50:59.287540Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15086075,
    events_root: None,
}
2023-01-25T06:50:59.287561Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 158
2023-01-25T06:50:59.287564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::158
2023-01-25T06:50:59.287566Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.287569Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.287570Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [22, 125, 25, 15, 118, 29, 85, 29, 170, 92, 159, 38, 55, 200, 77, 68, 234, 104, 167, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([9, 240, 5, 238, 205, 144, 121, 190, 117, 244, 171, 119, 221, 242, 93, 166, 187, 11, 249, 159]) }
2023-01-25T06:50:59.288233Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15758117,
    events_root: None,
}
2023-01-25T06:50:59.288254Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 159
2023-01-25T06:50:59.288257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::159
2023-01-25T06:50:59.288259Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.288263Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.288264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [196, 99, 207, 162, 98, 3, 238, 208, 156, 239, 251, 137, 251, 171, 111, 130, 62, 213, 18, 231, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([127, 22, 74, 146, 31, 240, 94, 4, 5, 0, 168, 124, 152, 159, 106, 186, 166, 245, 96, 1]) }
2023-01-25T06:50:59.288929Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16384489,
    events_root: None,
}
2023-01-25T06:50:59.288950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 160
2023-01-25T06:50:59.288953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::160
2023-01-25T06:50:59.288955Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.288958Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.288959Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [197, 146, 5, 66, 155, 102, 93, 206, 66, 119, 48, 227, 249, 60, 229, 162, 77, 34, 180, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([73, 61, 140, 212, 105, 148, 249, 14, 52, 230, 238, 162, 150, 154, 9, 21, 65, 159, 123, 114]) }
2023-01-25T06:50:59.289642Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16948011,
    events_root: None,
}
2023-01-25T06:50:59.289664Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 161
2023-01-25T06:50:59.289667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::161
2023-01-25T06:50:59.289670Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.289673Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.289674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [219, 194, 196, 194, 99, 99, 64, 121, 73, 125, 109, 149, 141, 193, 236, 104, 141, 110, 254, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([139, 5, 231, 32, 229, 212, 4, 215, 238, 97, 99, 197, 170, 49, 135, 202, 113, 170, 126, 42]) }
2023-01-25T06:50:59.290334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16287402,
    events_root: None,
}
2023-01-25T06:50:59.290356Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 162
2023-01-25T06:50:59.290358Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::162
2023-01-25T06:50:59.290360Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.290363Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.290364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [231, 80, 138, 74, 165, 2, 81, 24, 189, 31, 249, 159, 201, 152, 77, 61, 60, 61, 248, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([116, 63, 104, 161, 128, 157, 77, 211, 34, 225, 247, 206, 99, 136, 227, 1, 169, 47, 205, 63]) }
2023-01-25T06:50:59.290958Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12121744,
    events_root: None,
}
2023-01-25T06:50:59.290974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 163
2023-01-25T06:50:59.290977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::163
2023-01-25T06:50:59.290979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.290981Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.290983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [152, 57, 207, 122, 225, 208, 14, 193, 222, 39, 89, 17, 170, 77, 168, 251, 176, 243, 6, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([24, 23, 0, 25, 83, 60, 59, 147, 214, 85, 44, 223, 55, 32, 220, 231, 144, 240, 221, 9]) }
2023-01-25T06:50:59.291692Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15472974,
    events_root: None,
}
2023-01-25T06:50:59.291718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 164
2023-01-25T06:50:59.291721Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::164
2023-01-25T06:50:59.291723Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.291725Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.291727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [239, 219, 87, 208, 106, 139, 214, 152, 190, 61, 169, 165, 20, 95, 87, 111, 243, 85, 60, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([218, 18, 189, 93, 37, 195, 61, 200, 121, 174, 177, 80, 117, 158, 115, 198, 236, 94, 150, 60]) }
2023-01-25T06:50:59.292460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15429669,
    events_root: None,
}
2023-01-25T06:50:59.292480Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 165
2023-01-25T06:50:59.292484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::165
2023-01-25T06:50:59.292486Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.292488Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.292490Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [46, 52, 214, 248, 54, 191, 116, 81, 176, 209, 132, 27, 101, 5, 137, 204, 147, 170, 115, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([185, 91, 157, 88, 96, 101, 55, 73, 90, 229, 142, 243, 119, 115, 114, 183, 43, 146, 80, 225]) }
2023-01-25T06:50:59.293167Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16593560,
    events_root: None,
}
2023-01-25T06:50:59.293187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 166
2023-01-25T06:50:59.293190Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::166
2023-01-25T06:50:59.293192Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.293195Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.293196Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [25, 121, 197, 141, 38, 95, 79, 42, 227, 211, 168, 110, 197, 21, 108, 231, 252, 0, 106, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([56, 243, 246, 92, 115, 19, 198, 26, 238, 116, 138, 85, 63, 113, 173, 50, 124, 171, 198, 175]) }
2023-01-25T06:50:59.293864Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16563060,
    events_root: None,
}
2023-01-25T06:50:59.293885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 167
2023-01-25T06:50:59.293888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::London::167
2023-01-25T06:50:59.293890Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.293892Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.293896Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 4, 135, 208, 216, 93, 184, 27, 204, 200, 181, 216, 13, 114, 33, 118, 133, 167, 76, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([73, 186, 110, 150, 243, 78, 194, 219, 28, 109, 164, 54, 87, 70, 183, 24, 19, 38, 68, 186]) }
2023-01-25T06:50:59.294580Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16888096,
    events_root: None,
}
2023-01-25T06:50:59.294601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:50:59.294604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::0
2023-01-25T06:50:59.294606Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.294608Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.294610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 57, 242, 251, 111, 59, 77, 250, 182, 188, 150, 17, 2, 182, 87, 72, 101, 162, 199, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([233, 107, 20, 12, 37, 155, 50, 137, 233, 240, 196, 99, 127, 179, 80, 190, 4, 194, 225, 237]) }
2023-01-25T06:50:59.295323Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16506054,
    events_root: None,
}
2023-01-25T06:50:59.295344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T06:50:59.295347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::1
2023-01-25T06:50:59.295349Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.295351Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.295353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [134, 21, 2, 37, 240, 9, 5, 73, 185, 112, 58, 18, 76, 111, 120, 172, 62, 37, 122, 151, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 26, 191, 187, 28, 234, 77, 252, 28, 24, 75, 240, 211, 118, 185, 19, 78, 149, 70, 245]) }
2023-01-25T06:50:59.296036Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17109257,
    events_root: None,
}
2023-01-25T06:50:59.296058Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-25T06:50:59.296061Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::2
2023-01-25T06:50:59.296063Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.296066Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.296067Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [10, 76, 161, 106, 74, 231, 23, 204, 201, 177, 60, 3, 112, 21, 25, 50, 191, 218, 43, 219, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([201, 38, 38, 22, 62, 219, 150, 135, 177, 241, 59, 153, 34, 29, 22, 107, 242, 108, 195, 135]) }
2023-01-25T06:50:59.296722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16674204,
    events_root: None,
}
2023-01-25T06:50:59.296744Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-25T06:50:59.296746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::3
2023-01-25T06:50:59.296750Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.296753Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.296754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [199, 145, 134, 141, 143, 194, 11, 191, 214, 13, 52, 58, 234, 197, 34, 175, 208, 74, 83, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([145, 33, 89, 45, 120, 162, 235, 138, 158, 220, 105, 187, 248, 227, 88, 59, 111, 227, 175, 120]) }
2023-01-25T06:50:59.297414Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16867979,
    events_root: None,
}
2023-01-25T06:50:59.297435Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-25T06:50:59.297438Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::4
2023-01-25T06:50:59.297440Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.297443Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.297444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [30, 92, 70, 128, 202, 222, 192, 241, 102, 209, 201, 62, 189, 208, 138, 220, 244, 37, 191, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([92, 78, 32, 183, 20, 116, 160, 24, 93, 13, 74, 60, 71, 47, 68, 214, 9, 69, 33, 242]) }
2023-01-25T06:50:59.298150Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17334455,
    events_root: None,
}
2023-01-25T06:50:59.298173Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-25T06:50:59.298175Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::5
2023-01-25T06:50:59.298178Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.298180Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.298182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [45, 190, 110, 50, 236, 246, 126, 155, 169, 156, 158, 43, 86, 206, 16, 203, 140, 9, 197, 195, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([29, 170, 11, 152, 113, 250, 63, 241, 164, 232, 205, 177, 191, 59, 170, 2, 166, 154, 6, 141]) }
2023-01-25T06:50:59.298930Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18341184,
    events_root: None,
}
2023-01-25T06:50:59.298953Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-25T06:50:59.298956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::6
2023-01-25T06:50:59.298959Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.298962Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.298963Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [12, 185, 123, 156, 249, 60, 141, 112, 137, 191, 205, 230, 167, 26, 67, 8, 105, 179, 175, 91, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([224, 127, 142, 26, 16, 56, 223, 204, 58, 154, 158, 13, 80, 107, 194, 252, 198, 89, 188, 114]) }
2023-01-25T06:50:59.299664Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18824645,
    events_root: None,
}
2023-01-25T06:50:59.299688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-25T06:50:59.299691Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::7
2023-01-25T06:50:59.299694Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.299697Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.299698Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [123, 95, 227, 82, 192, 142, 98, 196, 59, 200, 20, 204, 109, 228, 192, 232, 31, 166, 160, 168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([83, 242, 32, 232, 142, 92, 253, 105, 158, 39, 47, 205, 245, 242, 166, 27, 224, 56, 84, 129]) }
2023-01-25T06:50:59.300419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18665946,
    events_root: None,
}
2023-01-25T06:50:59.300444Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-25T06:50:59.300448Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::8
2023-01-25T06:50:59.300450Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.300453Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.300454Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [245, 171, 160, 170, 151, 94, 121, 108, 245, 141, 9, 119, 234, 45, 232, 206, 156, 218, 182, 87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 12, 253, 213, 163, 63, 29, 115, 178, 187, 161, 163, 212, 193, 125, 27, 3, 62, 7, 249]) }
2023-01-25T06:50:59.301035Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14862920,
    events_root: None,
}
2023-01-25T06:50:59.301054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-25T06:50:59.301057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::9
2023-01-25T06:50:59.301060Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.301062Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.301065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [170, 69, 26, 33, 205, 228, 89, 242, 202, 115, 169, 108, 3, 220, 159, 135, 62, 178, 37, 87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([10, 31, 101, 35, 215, 26, 74, 181, 210, 246, 179, 103, 102, 200, 253, 136, 135, 201, 30, 222]) }
2023-01-25T06:50:59.301741Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16883907,
    events_root: None,
}
2023-01-25T06:50:59.301763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-25T06:50:59.301766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::10
2023-01-25T06:50:59.301768Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.301771Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.301773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [112, 37, 201, 1, 30, 223, 19, 18, 73, 241, 214, 209, 129, 68, 234, 90, 168, 212, 165, 243, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([111, 101, 131, 235, 47, 251, 193, 19, 227, 95, 161, 71, 165, 135, 114, 55, 251, 221, 137, 48]) }
2023-01-25T06:50:59.302461Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17212783,
    events_root: None,
}
2023-01-25T06:50:59.302482Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-25T06:50:59.302485Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::11
2023-01-25T06:50:59.302487Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.302489Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.302491Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [237, 122, 115, 210, 145, 226, 175, 198, 158, 188, 175, 228, 204, 218, 219, 241, 53, 45, 217, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 102, 203, 126, 45, 108, 207, 145, 210, 218, 252, 249, 122, 133, 241, 60, 219, 42, 234, 109]) }
2023-01-25T06:50:59.303228Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18508948,
    events_root: None,
}
2023-01-25T06:50:59.303251Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-25T06:50:59.303254Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::12
2023-01-25T06:50:59.303256Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.303258Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.303261Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [239, 138, 19, 5, 46, 255, 234, 177, 217, 69, 89, 157, 85, 249, 147, 33, 217, 39, 121, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([196, 98, 194, 59, 213, 64, 206, 31, 14, 190, 130, 228, 239, 109, 211, 237, 18, 175, 83, 144]) }
2023-01-25T06:50:59.304013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18682799,
    events_root: None,
}
2023-01-25T06:50:59.304036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-25T06:50:59.304039Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::13
2023-01-25T06:50:59.304041Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.304043Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.304045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [221, 31, 44, 207, 152, 233, 87, 153, 68, 148, 90, 85, 45, 0, 251, 146, 120, 232, 83, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([71, 70, 230, 190, 48, 241, 157, 172, 217, 73, 0, 165, 128, 235, 16, 135, 37, 189, 190, 113]) }
2023-01-25T06:50:59.304790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18864279,
    events_root: None,
}
2023-01-25T06:50:59.304814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-25T06:50:59.304817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::14
2023-01-25T06:50:59.304820Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.304822Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.304824Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.305123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5003366,
    events_root: None,
}
2023-01-25T06:50:59.305136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-25T06:50:59.305138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::15
2023-01-25T06:50:59.305141Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.305143Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.305145Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.305416Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4047832,
    events_root: None,
}
2023-01-25T06:50:59.305428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-25T06:50:59.305431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::16
2023-01-25T06:50:59.305433Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.305436Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.305437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.305709Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4047832,
    events_root: None,
}
2023-01-25T06:50:59.305721Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-25T06:50:59.305723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::17
2023-01-25T06:50:59.305726Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.305728Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.305729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.305999Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4047832,
    events_root: None,
}
2023-01-25T06:50:59.306011Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-25T06:50:59.306013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::18
2023-01-25T06:50:59.306015Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.306018Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.306019Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.306340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4047832,
    events_root: None,
}
2023-01-25T06:50:59.306353Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-25T06:50:59.306356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::19
2023-01-25T06:50:59.306358Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.306360Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.306362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.306644Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5003322,
    events_root: None,
}
2023-01-25T06:50:59.306657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-25T06:50:59.306660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::20
2023-01-25T06:50:59.306662Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.306665Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.306666Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.306947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5003322,
    events_root: None,
}
2023-01-25T06:50:59.306960Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-25T06:50:59.306963Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::21
2023-01-25T06:50:59.306965Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.306967Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.306969Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.307249Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5003322,
    events_root: None,
}
2023-01-25T06:50:59.307262Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-25T06:50:59.307265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::22
2023-01-25T06:50:59.307267Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.307270Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.307271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.307557Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5003366,
    events_root: None,
}
2023-01-25T06:50:59.307572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-25T06:50:59.307575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::23
2023-01-25T06:50:59.307579Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.307581Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.307583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.307859Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4047832,
    events_root: None,
}
2023-01-25T06:50:59.307873Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-25T06:50:59.307876Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::24
2023-01-25T06:50:59.307879Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.307883Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.307884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.308184Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4047832,
    events_root: None,
}
2023-01-25T06:50:59.308196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-25T06:50:59.308199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::25
2023-01-25T06:50:59.308202Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.308204Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.308205Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.308497Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5003322,
    events_root: None,
}
2023-01-25T06:50:59.308510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-25T06:50:59.308512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::26
2023-01-25T06:50:59.308514Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.308517Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.308518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.308863Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5003322,
    events_root: None,
}
2023-01-25T06:50:59.308876Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-25T06:50:59.308878Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::27
2023-01-25T06:50:59.308880Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.308883Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.308884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.309166Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5003322,
    events_root: None,
}
2023-01-25T06:50:59.309179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-25T06:50:59.309181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::28
2023-01-25T06:50:59.309184Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.309188Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.309189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.309537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7606591,
    events_root: None,
}
2023-01-25T06:50:59.309556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-25T06:50:59.309559Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::29
2023-01-25T06:50:59.309561Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.309564Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.309565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.309899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6233428,
    events_root: None,
}
2023-01-25T06:50:59.309914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-25T06:50:59.309918Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::30
2023-01-25T06:50:59.309920Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.309923Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.309924Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.310263Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7616198,
    events_root: None,
}
2023-01-25T06:50:59.310279Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-25T06:50:59.310282Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::31
2023-01-25T06:50:59.310285Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.310289Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.310290Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.310625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6696807,
    events_root: None,
}
2023-01-25T06:50:59.310640Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-25T06:50:59.310642Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::32
2023-01-25T06:50:59.310645Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.310647Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.310649Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.310979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6712569,
    events_root: None,
}
2023-01-25T06:50:59.310995Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-25T06:50:59.310997Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::33
2023-01-25T06:50:59.310999Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.311002Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.311003Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.311333Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6714156,
    events_root: None,
}
2023-01-25T06:50:59.311348Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-25T06:50:59.311352Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::34
2023-01-25T06:50:59.311354Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.311356Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.311358Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.311753Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6801691,
    events_root: None,
}
2023-01-25T06:50:59.311768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-25T06:50:59.311771Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::35
2023-01-25T06:50:59.311773Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.311776Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.311778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.312136Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6801719,
    events_root: None,
}
2023-01-25T06:50:59.312152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 36
2023-01-25T06:50:59.312155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::36
2023-01-25T06:50:59.312157Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.312160Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.312161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.312422Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5512805,
    events_root: None,
}
2023-01-25T06:50:59.312434Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 37
2023-01-25T06:50:59.312437Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::37
2023-01-25T06:50:59.312439Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.312442Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.312444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.312790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7446493,
    events_root: None,
}
2023-01-25T06:50:59.312805Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 38
2023-01-25T06:50:59.312808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::38
2023-01-25T06:50:59.312810Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.312812Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.312815Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.313151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6748624,
    events_root: None,
}
2023-01-25T06:50:59.313166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 39
2023-01-25T06:50:59.313169Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::39
2023-01-25T06:50:59.313171Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.313174Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.313175Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.313510Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6750211,
    events_root: None,
}
2023-01-25T06:50:59.313525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 40
2023-01-25T06:50:59.313528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::40
2023-01-25T06:50:59.313530Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.313533Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.313534Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.313879Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6836209,
    events_root: None,
}
2023-01-25T06:50:59.313895Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 41
2023-01-25T06:50:59.313897Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::41
2023-01-25T06:50:59.313899Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.313902Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.313903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.314243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6836237,
    events_root: None,
}
2023-01-25T06:50:59.314258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 42
2023-01-25T06:50:59.314260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::42
2023-01-25T06:50:59.314262Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.314265Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.314266Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.314405Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.314411Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.314425Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 43
2023-01-25T06:50:59.314428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::43
2023-01-25T06:50:59.314431Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.314435Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.314437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.314560Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.314565Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.314574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 44
2023-01-25T06:50:59.314576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::44
2023-01-25T06:50:59.314578Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.314580Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.314582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.314684Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.314689Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.314698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 45
2023-01-25T06:50:59.314700Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::45
2023-01-25T06:50:59.314701Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.314704Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.314705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.314804Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.314809Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.314817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 46
2023-01-25T06:50:59.314819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::46
2023-01-25T06:50:59.314822Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.314825Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.314826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.314925Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.314929Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.314938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 47
2023-01-25T06:50:59.314940Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::47
2023-01-25T06:50:59.314942Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.314944Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.314945Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.315045Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.315050Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.315058Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 48
2023-01-25T06:50:59.315060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::48
2023-01-25T06:50:59.315063Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.315066Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.315068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.315199Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.315205Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.315217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 49
2023-01-25T06:50:59.315221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::49
2023-01-25T06:50:59.315223Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.315227Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.315229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.315338Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.315343Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.315351Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 50
2023-01-25T06:50:59.315354Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::50
2023-01-25T06:50:59.315355Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.315358Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.315359Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.315460Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.315466Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.315475Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 51
2023-01-25T06:50:59.315478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::51
2023-01-25T06:50:59.315480Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.315483Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.315484Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.315582Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.315587Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.315595Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 52
2023-01-25T06:50:59.315597Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::52
2023-01-25T06:50:59.315599Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.315602Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.315603Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.315703Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.315707Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.315716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 53
2023-01-25T06:50:59.315718Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::53
2023-01-25T06:50:59.315721Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.315723Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.315724Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.315854Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.315860Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.315872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 54
2023-01-25T06:50:59.315875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::54
2023-01-25T06:50:59.315878Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.315882Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.315884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.316001Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.316006Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.316014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 55
2023-01-25T06:50:59.316017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::55
2023-01-25T06:50:59.316019Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.316021Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.316022Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.316122Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1687992,
    events_root: None,
}
2023-01-25T06:50:59.316126Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=509): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.316135Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 56
2023-01-25T06:50:59.316138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::56
2023-01-25T06:50:59.316140Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.316143Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.316144Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.316582Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9189087,
    events_root: None,
}
2023-01-25T06:50:59.316601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 57
2023-01-25T06:50:59.316604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::57
2023-01-25T06:50:59.316606Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.316608Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.316610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.317047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9225371,
    events_root: None,
}
2023-01-25T06:50:59.317065Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 58
2023-01-25T06:50:59.317067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::58
2023-01-25T06:50:59.317069Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.317073Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.317074Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.317502Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9178076,
    events_root: None,
}
2023-01-25T06:50:59.317521Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 59
2023-01-25T06:50:59.317523Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::59
2023-01-25T06:50:59.317525Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.317529Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.317531Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.318011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9180764,
    events_root: None,
}
2023-01-25T06:50:59.318028Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 60
2023-01-25T06:50:59.318031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::60
2023-01-25T06:50:59.318033Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.318036Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.318037Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.318478Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9193402,
    events_root: None,
}
2023-01-25T06:50:59.318498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 61
2023-01-25T06:50:59.318500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::61
2023-01-25T06:50:59.318502Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.318505Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.318506Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.318947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9195000,
    events_root: None,
}
2023-01-25T06:50:59.318964Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 62
2023-01-25T06:50:59.318967Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::62
2023-01-25T06:50:59.318969Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.318971Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.318973Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.319413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9282523,
    events_root: None,
}
2023-01-25T06:50:59.319431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 63
2023-01-25T06:50:59.319434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::63
2023-01-25T06:50:59.319436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.319438Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.319440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.319876Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9282552,
    events_root: None,
}
2023-01-25T06:50:59.319898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 64
2023-01-25T06:50:59.319902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::64
2023-01-25T06:50:59.319905Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.319907Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.319908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.320236Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6614560,
    events_root: None,
}
2023-01-25T06:50:59.320250Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 65
2023-01-25T06:50:59.320253Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::65
2023-01-25T06:50:59.320255Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.320257Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.320259Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.320697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9221394,
    events_root: None,
}
2023-01-25T06:50:59.320715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 66
2023-01-25T06:50:59.320718Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::66
2023-01-25T06:50:59.320720Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.320722Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.320724Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.321161Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9229457,
    events_root: None,
}
2023-01-25T06:50:59.321179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 67
2023-01-25T06:50:59.321181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::67
2023-01-25T06:50:59.321184Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.321187Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.321189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.321630Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9231054,
    events_root: None,
}
2023-01-25T06:50:59.321650Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 68
2023-01-25T06:50:59.321653Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::68
2023-01-25T06:50:59.321656Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.321660Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.321662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.322159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9317042,
    events_root: None,
}
2023-01-25T06:50:59.322176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 69
2023-01-25T06:50:59.322179Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::69
2023-01-25T06:50:59.322181Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.322183Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.322185Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.322625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9317070,
    events_root: None,
}
2023-01-25T06:50:59.322643Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 70
2023-01-25T06:50:59.322646Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::70
2023-01-25T06:50:59.322648Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.322652Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.322653Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.322959Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5765583,
    events_root: None,
}
2023-01-25T06:50:59.322974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 71
2023-01-25T06:50:59.322977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::71
2023-01-25T06:50:59.322979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.322981Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.322983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.323289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5827923,
    events_root: None,
}
2023-01-25T06:50:59.323303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 72
2023-01-25T06:50:59.323307Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::72
2023-01-25T06:50:59.323310Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.323313Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.323315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.323616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5760519,
    events_root: None,
}
2023-01-25T06:50:59.323631Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 73
2023-01-25T06:50:59.323633Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::73
2023-01-25T06:50:59.323636Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.323638Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.323640Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.323934Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4845992,
    events_root: None,
}
2023-01-25T06:50:59.323949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 74
2023-01-25T06:50:59.323951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::74
2023-01-25T06:50:59.323954Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.323956Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.323958Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.324247Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4861671,
    events_root: None,
}
2023-01-25T06:50:59.324262Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 75
2023-01-25T06:50:59.324265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::75
2023-01-25T06:50:59.324267Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.324269Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.324271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.324583Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4861947,
    events_root: None,
}
2023-01-25T06:50:59.324599Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 76
2023-01-25T06:50:59.324602Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::76
2023-01-25T06:50:59.324605Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.324608Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.324610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.324974Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4949470,
    events_root: None,
}
2023-01-25T06:50:59.324988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 77
2023-01-25T06:50:59.324992Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::77
2023-01-25T06:50:59.324994Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.324997Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.324998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.325291Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4949499,
    events_root: None,
}
2023-01-25T06:50:59.325305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 78
2023-01-25T06:50:59.325307Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::78
2023-01-25T06:50:59.325309Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.325312Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.325313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.325548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4257566,
    events_root: None,
}
2023-01-25T06:50:59.325559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 79
2023-01-25T06:50:59.325562Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::79
2023-01-25T06:50:59.325563Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.325566Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.325567Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.325877Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5826514,
    events_root: None,
}
2023-01-25T06:50:59.325892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 80
2023-01-25T06:50:59.325894Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::80
2023-01-25T06:50:59.325896Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.325899Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.325900Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.326194Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4920726,
    events_root: None,
}
2023-01-25T06:50:59.326207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 81
2023-01-25T06:50:59.326210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::81
2023-01-25T06:50:59.326212Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.326214Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.326216Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.326510Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4921002,
    events_root: None,
}
2023-01-25T06:50:59.326525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 82
2023-01-25T06:50:59.326528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::82
2023-01-25T06:50:59.326530Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.326533Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.326534Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.326838Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5006990,
    events_root: None,
}
2023-01-25T06:50:59.326853Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 83
2023-01-25T06:50:59.326856Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::83
2023-01-25T06:50:59.326858Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.326860Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.326862Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.327161Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5007018,
    events_root: None,
}
2023-01-25T06:50:59.327175Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 84
2023-01-25T06:50:59.327178Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::84
2023-01-25T06:50:59.327180Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.327183Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.327184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.327556Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5750494,
    events_root: None,
}
2023-01-25T06:50:59.327572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 85
2023-01-25T06:50:59.327575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::85
2023-01-25T06:50:59.327576Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.327579Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.327580Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.327901Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5789602,
    events_root: None,
}
2023-01-25T06:50:59.327920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 86
2023-01-25T06:50:59.327923Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::86
2023-01-25T06:50:59.327925Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.327927Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.327929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.328228Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5744666,
    events_root: None,
}
2023-01-25T06:50:59.328242Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 87
2023-01-25T06:50:59.328245Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::87
2023-01-25T06:50:59.328247Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.328249Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.328252Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.328533Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4827803,
    events_root: None,
}
2023-01-25T06:50:59.328546Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 88
2023-01-25T06:50:59.328549Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::88
2023-01-25T06:50:59.328551Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.328554Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.328555Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.328836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4844770,
    events_root: None,
}
2023-01-25T06:50:59.328850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 89
2023-01-25T06:50:59.328852Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::89
2023-01-25T06:50:59.328855Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.328857Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.328859Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.329139Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4845046,
    events_root: None,
}
2023-01-25T06:50:59.329153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 90
2023-01-25T06:50:59.329156Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::90
2023-01-25T06:50:59.329158Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.329162Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.329163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.329449Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4932569,
    events_root: None,
}
2023-01-25T06:50:59.329464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 91
2023-01-25T06:50:59.329467Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::91
2023-01-25T06:50:59.329469Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.329471Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.329473Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.329760Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4932598,
    events_root: None,
}
2023-01-25T06:50:59.329774Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 92
2023-01-25T06:50:59.329776Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::92
2023-01-25T06:50:59.329778Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.329781Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.329782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.330070Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4218189,
    events_root: None,
}
2023-01-25T06:50:59.330082Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 93
2023-01-25T06:50:59.330085Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::93
2023-01-25T06:50:59.330088Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.330090Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.330092Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.330395Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5787281,
    events_root: None,
}
2023-01-25T06:50:59.330410Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 94
2023-01-25T06:50:59.330413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::94
2023-01-25T06:50:59.330415Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.330417Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.330419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.330709Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4880825,
    events_root: None,
}
2023-01-25T06:50:59.330723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 95
2023-01-25T06:50:59.330725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::95
2023-01-25T06:50:59.330728Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.330730Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.330731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.331026Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4881100,
    events_root: None,
}
2023-01-25T06:50:59.331040Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 96
2023-01-25T06:50:59.331043Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::96
2023-01-25T06:50:59.331045Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.331047Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.331049Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.331350Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4967088,
    events_root: None,
}
2023-01-25T06:50:59.331365Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 97
2023-01-25T06:50:59.331368Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::97
2023-01-25T06:50:59.331370Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.331373Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.331374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.331671Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4967116,
    events_root: None,
}
2023-01-25T06:50:59.331685Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 98
2023-01-25T06:50:59.331688Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::98
2023-01-25T06:50:59.331690Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.331693Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.331695Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.331800Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.331805Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.331815Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 99
2023-01-25T06:50:59.331817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::99
2023-01-25T06:50:59.331819Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.331821Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.331823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.331930Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.331935Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.331944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 100
2023-01-25T06:50:59.331947Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::100
2023-01-25T06:50:59.331950Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.331953Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.331955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.332089Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.332095Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.332107Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 101
2023-01-25T06:50:59.332110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::101
2023-01-25T06:50:59.332113Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.332117Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.332119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.332233Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.332239Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.332248Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 102
2023-01-25T06:50:59.332250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::102
2023-01-25T06:50:59.332252Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.332254Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.332256Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.332356Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.332360Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.332369Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 103
2023-01-25T06:50:59.332371Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::103
2023-01-25T06:50:59.332373Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.332375Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.332376Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.332476Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.332481Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.332489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 104
2023-01-25T06:50:59.332491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::104
2023-01-25T06:50:59.332493Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.332496Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.332497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.332597Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.332603Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.332611Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 105
2023-01-25T06:50:59.332614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::105
2023-01-25T06:50:59.332616Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.332619Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.332621Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.332753Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.332759Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.332771Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 106
2023-01-25T06:50:59.332774Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::106
2023-01-25T06:50:59.332777Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.332780Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.332782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.332890Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.332897Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.332906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 107
2023-01-25T06:50:59.332908Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::107
2023-01-25T06:50:59.332910Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.332913Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.332914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.333012Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.333017Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.333026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 108
2023-01-25T06:50:59.333028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::108
2023-01-25T06:50:59.333030Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.333033Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.333034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.333134Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.333138Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.333147Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 109
2023-01-25T06:50:59.333150Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::109
2023-01-25T06:50:59.333151Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.333154Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.333155Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.333253Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.333259Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.333268Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 110
2023-01-25T06:50:59.333271Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::110
2023-01-25T06:50:59.333273Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.333275Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.333276Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.333406Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.333412Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.333424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 111
2023-01-25T06:50:59.333427Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::111
2023-01-25T06:50:59.333430Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.333433Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.333435Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.333549Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1691656,
    events_root: None,
}
2023-01-25T06:50:59.333555Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=541): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:50:59.333563Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 112
2023-01-25T06:50:59.333566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::112
2023-01-25T06:50:59.333569Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.333571Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.333573Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.333950Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6693921,
    events_root: None,
}
2023-01-25T06:50:59.333966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 113
2023-01-25T06:50:59.333969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::113
2023-01-25T06:50:59.333971Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.333973Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.333975Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.334352Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6733769,
    events_root: None,
}
2023-01-25T06:50:59.334370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 114
2023-01-25T06:50:59.334373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::114
2023-01-25T06:50:59.334375Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.334378Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.334379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.334754Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6687569,
    events_root: None,
}
2023-01-25T06:50:59.334769Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 115
2023-01-25T06:50:59.334772Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::115
2023-01-25T06:50:59.334774Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.334777Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.334778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.335134Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5771230,
    events_root: None,
}
2023-01-25T06:50:59.335149Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 116
2023-01-25T06:50:59.335152Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::116
2023-01-25T06:50:59.335155Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.335157Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.335159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.335513Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5788197,
    events_root: None,
}
2023-01-25T06:50:59.335530Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 117
2023-01-25T06:50:59.335533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::117
2023-01-25T06:50:59.335535Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.335537Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.335539Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.335958Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5788473,
    events_root: None,
}
2023-01-25T06:50:59.335976Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 118
2023-01-25T06:50:59.335978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::118
2023-01-25T06:50:59.335980Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.335983Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.335984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.336347Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5875996,
    events_root: None,
}
2023-01-25T06:50:59.336362Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 119
2023-01-25T06:50:59.336365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::119
2023-01-25T06:50:59.336367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.336369Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.336371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.336735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5876025,
    events_root: None,
}
2023-01-25T06:50:59.336751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 120
2023-01-25T06:50:59.336753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::120
2023-01-25T06:50:59.336756Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.336758Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.336759Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.337056Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5162487,
    events_root: None,
}
2023-01-25T06:50:59.337071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 121
2023-01-25T06:50:59.337073Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::121
2023-01-25T06:50:59.337076Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.337078Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.337079Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.337457Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6731071,
    events_root: None,
}
2023-01-25T06:50:59.337473Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 122
2023-01-25T06:50:59.337476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::122
2023-01-25T06:50:59.337478Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.337481Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.337482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.337845Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5824759,
    events_root: None,
}
2023-01-25T06:50:59.337861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 123
2023-01-25T06:50:59.337863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::123
2023-01-25T06:50:59.337866Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.337869Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.337871Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.338231Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5825035,
    events_root: None,
}
2023-01-25T06:50:59.338247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 124
2023-01-25T06:50:59.338250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::124
2023-01-25T06:50:59.338252Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.338255Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.338256Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.338622Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5911023,
    events_root: None,
}
2023-01-25T06:50:59.338638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 125
2023-01-25T06:50:59.338641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::125
2023-01-25T06:50:59.338643Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.338646Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.338648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.339079Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5911051,
    events_root: None,
}
2023-01-25T06:50:59.339095Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 126
2023-01-25T06:50:59.339098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::126
2023-01-25T06:50:59.339100Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.339102Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.339104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.339402Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5725080,
    events_root: None,
}
2023-01-25T06:50:59.339418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 127
2023-01-25T06:50:59.339421Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::127
2023-01-25T06:50:59.339423Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.339426Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.339428Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.339731Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5786681,
    events_root: None,
}
2023-01-25T06:50:59.339746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 128
2023-01-25T06:50:59.339748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::128
2023-01-25T06:50:59.339751Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.339753Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.339754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.340053Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5719253,
    events_root: None,
}
2023-01-25T06:50:59.340069Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 129
2023-01-25T06:50:59.340071Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::129
2023-01-25T06:50:59.340074Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.340076Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.340078Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.340357Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4802390,
    events_root: None,
}
2023-01-25T06:50:59.340370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 130
2023-01-25T06:50:59.340373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::130
2023-01-25T06:50:59.340375Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.340378Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.340379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.340656Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4819356,
    events_root: None,
}
2023-01-25T06:50:59.340670Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 131
2023-01-25T06:50:59.340672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::131
2023-01-25T06:50:59.340674Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.340678Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.340679Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.340970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4819632,
    events_root: None,
}
2023-01-25T06:50:59.340984Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 132
2023-01-25T06:50:59.340987Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::132
2023-01-25T06:50:59.340989Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.340992Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.340994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.341301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4907156,
    events_root: None,
}
2023-01-25T06:50:59.341316Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 133
2023-01-25T06:50:59.341321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::133
2023-01-25T06:50:59.341323Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.341325Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.341327Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.341610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4907184,
    events_root: None,
}
2023-01-25T06:50:59.341625Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 134
2023-01-25T06:50:59.341629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::134
2023-01-25T06:50:59.341631Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.341635Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.341637Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.341919Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4215268,
    events_root: None,
}
2023-01-25T06:50:59.341931Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 135
2023-01-25T06:50:59.341934Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::135
2023-01-25T06:50:59.341936Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.341939Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.341940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.342244Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5784360,
    events_root: None,
}
2023-01-25T06:50:59.342261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 136
2023-01-25T06:50:59.342264Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::136
2023-01-25T06:50:59.342266Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.342268Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.342270Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.342560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4877904,
    events_root: None,
}
2023-01-25T06:50:59.342573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 137
2023-01-25T06:50:59.342576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::137
2023-01-25T06:50:59.342578Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.342580Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.342582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.342870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4878179,
    events_root: None,
}
2023-01-25T06:50:59.342884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 138
2023-01-25T06:50:59.342886Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::138
2023-01-25T06:50:59.342889Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.342891Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.342893Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.343187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4964167,
    events_root: None,
}
2023-01-25T06:50:59.343201Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 139
2023-01-25T06:50:59.343204Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::139
2023-01-25T06:50:59.343206Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.343208Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.343212Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:50:59.343506Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4964195,
    events_root: None,
}
2023-01-25T06:50:59.343520Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 140
2023-01-25T06:50:59.343523Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::140
2023-01-25T06:50:59.343526Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.343528Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.343530Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [106, 106, 163, 252, 185, 75, 136, 144, 115, 131, 103, 68, 215, 158, 131, 81, 49, 222, 207, 146, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([97, 174, 177, 201, 114, 120, 98, 173, 73, 35, 140, 150, 210, 42, 73, 63, 224, 227, 123, 238]) }
2023-01-25T06:50:59.344428Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16664383,
    events_root: None,
}
2023-01-25T06:50:59.344454Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 141
2023-01-25T06:50:59.344457Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::141
2023-01-25T06:50:59.344460Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.344463Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.344464Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [132, 182, 253, 3, 215, 150, 81, 38, 246, 42, 182, 87, 209, 201, 93, 54, 36, 17, 199, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 26, 218, 136, 54, 131, 12, 3, 54, 184, 217, 150, 250, 224, 100, 33, 120, 15, 180, 222]) }
2023-01-25T06:50:59.345224Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15579701,
    events_root: None,
}
2023-01-25T06:50:59.345246Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 142
2023-01-25T06:50:59.345249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::142
2023-01-25T06:50:59.345251Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.345254Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.345255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [14, 171, 166, 88, 198, 240, 164, 212, 14, 209, 186, 244, 101, 119, 164, 130, 164, 161, 213, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([64, 248, 54, 129, 215, 152, 69, 226, 199, 154, 99, 48, 210, 55, 190, 142, 170, 54, 178, 250]) }
2023-01-25T06:50:59.345904Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15373791,
    events_root: None,
}
2023-01-25T06:50:59.345927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 143
2023-01-25T06:50:59.345930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::143
2023-01-25T06:50:59.345932Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.345935Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.345936Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [105, 79, 234, 100, 71, 36, 216, 174, 31, 175, 150, 253, 96, 20, 123, 166, 31, 172, 255, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 210, 73, 223, 169, 243, 50, 204, 123, 142, 76, 211, 250, 176, 210, 141, 170, 42, 164, 125]) }
2023-01-25T06:50:59.346595Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16065430,
    events_root: None,
}
2023-01-25T06:50:59.346617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 144
2023-01-25T06:50:59.346619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::144
2023-01-25T06:50:59.346622Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.346624Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.346625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [18, 75, 124, 139, 86, 167, 108, 206, 104, 250, 12, 175, 86, 120, 99, 160, 13, 172, 102, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([83, 22, 236, 114, 253, 231, 243, 179, 191, 237, 119, 192, 164, 196, 184, 222, 37, 19, 79, 84]) }
2023-01-25T06:50:59.347278Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15642751,
    events_root: None,
}
2023-01-25T06:50:59.347299Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 145
2023-01-25T06:50:59.347303Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::145
2023-01-25T06:50:59.347305Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.347308Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.347310Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [50, 228, 93, 42, 145, 19, 157, 207, 18, 196, 38, 81, 60, 239, 63, 201, 136, 123, 67, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([242, 168, 62, 123, 115, 51, 145, 17, 0, 11, 61, 31, 182, 154, 64, 14, 126, 99, 133, 234]) }
2023-01-25T06:50:59.348005Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16779973,
    events_root: None,
}
2023-01-25T06:50:59.348027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 146
2023-01-25T06:50:59.348030Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::146
2023-01-25T06:50:59.348033Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.348035Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.348039Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [74, 230, 6, 238, 101, 194, 250, 238, 226, 50, 115, 48, 110, 53, 167, 230, 114, 236, 83, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([195, 12, 169, 231, 217, 150, 127, 224, 228, 236, 133, 227, 79, 106, 179, 54, 248, 83, 25, 176]) }
2023-01-25T06:50:59.348713Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16593811,
    events_root: None,
}
2023-01-25T06:50:59.348737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 147
2023-01-25T06:50:59.348741Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::147
2023-01-25T06:50:59.348743Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.348747Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.348749Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [127, 74, 77, 144, 166, 249, 183, 175, 232, 90, 33, 89, 40, 93, 28, 137, 227, 7, 149, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([64, 246, 237, 81, 54, 102, 49, 147, 90, 42, 233, 154, 124, 25, 119, 224, 237, 213, 255, 178]) }
2023-01-25T06:50:59.349470Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16981067,
    events_root: None,
}
2023-01-25T06:50:59.349490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 148
2023-01-25T06:50:59.349494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::148
2023-01-25T06:50:59.349496Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.349499Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.349501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [50, 255, 65, 138, 111, 45, 235, 203, 219, 150, 177, 238, 15, 165, 245, 135, 188, 250, 183, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([41, 235, 99, 150, 178, 91, 236, 177, 51, 242, 200, 231, 183, 53, 59, 146, 244, 76, 76, 98]) }
2023-01-25T06:50:59.350060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13235072,
    events_root: None,
}
2023-01-25T06:50:59.350077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 149
2023-01-25T06:50:59.350079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::149
2023-01-25T06:50:59.350082Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.350084Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.350086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [154, 120, 13, 115, 108, 123, 98, 86, 141, 246, 98, 68, 63, 16, 2, 255, 230, 145, 160, 179, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 13, 157, 172, 176, 114, 87, 154, 126, 34, 188, 20, 41, 173, 15, 163, 208, 159, 214, 54]) }
2023-01-25T06:50:59.350738Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15561445,
    events_root: None,
}
2023-01-25T06:50:59.350760Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 150
2023-01-25T06:50:59.350763Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::150
2023-01-25T06:50:59.350765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.350768Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.350770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [73, 217, 114, 130, 159, 19, 240, 14, 65, 210, 216, 165, 13, 191, 55, 146, 88, 241, 29, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([43, 153, 153, 151, 7, 100, 35, 29, 81, 219, 220, 164, 247, 226, 90, 83, 45, 156, 235, 74]) }
2023-01-25T06:50:59.351427Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15602443,
    events_root: None,
}
2023-01-25T06:50:59.351448Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 151
2023-01-25T06:50:59.351452Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::151
2023-01-25T06:50:59.351454Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.351456Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.351458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [8, 131, 65, 190, 182, 199, 65, 52, 42, 110, 46, 180, 54, 224, 224, 158, 210, 91, 199, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([95, 237, 89, 139, 110, 49, 65, 224, 60, 60, 20, 229, 3, 22, 21, 4, 58, 55, 198, 210]) }
2023-01-25T06:50:59.352137Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16384110,
    events_root: None,
}
2023-01-25T06:50:59.352158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 152
2023-01-25T06:50:59.352161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::152
2023-01-25T06:50:59.352163Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.352165Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.352167Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 95, 235, 56, 237, 5, 172, 184, 195, 72, 90, 57, 197, 142, 225, 222, 214, 146, 19, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([105, 205, 236, 113, 108, 6, 4, 33, 195, 172, 235, 69, 231, 194, 10, 70, 44, 57, 179, 196]) }
2023-01-25T06:50:59.352947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16996602,
    events_root: None,
}
2023-01-25T06:50:59.352968Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 153
2023-01-25T06:50:59.352970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::153
2023-01-25T06:50:59.352973Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.352976Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.352977Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [211, 50, 250, 4, 182, 221, 115, 252, 136, 8, 157, 76, 144, 85, 3, 30, 236, 183, 20, 215, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([181, 234, 212, 57, 130, 55, 33, 105, 194, 150, 21, 133, 199, 153, 93, 4, 88, 59, 115, 186]) }
2023-01-25T06:50:59.353695Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16925064,
    events_root: None,
}
2023-01-25T06:50:59.353719Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 154
2023-01-25T06:50:59.353723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::154
2023-01-25T06:50:59.353725Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.353728Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.353729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [25, 113, 216, 77, 174, 110, 112, 65, 17, 241, 34, 169, 219, 145, 104, 31, 248, 196, 45, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([200, 217, 188, 25, 220, 251, 23, 179, 218, 227, 166, 22, 94, 144, 26, 60, 73, 8, 70, 138]) }
2023-01-25T06:50:59.354419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16657041,
    events_root: None,
}
2023-01-25T06:50:59.354441Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 155
2023-01-25T06:50:59.354444Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::155
2023-01-25T06:50:59.354446Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.354449Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.354450Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [102, 136, 233, 182, 19, 57, 244, 216, 191, 241, 181, 246, 26, 60, 139, 71, 6, 173, 253, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([31, 163, 144, 252, 182, 248, 233, 152, 102, 202, 123, 160, 52, 25, 182, 48, 42, 126, 125, 127]) }
2023-01-25T06:50:59.355121Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15802702,
    events_root: None,
}
2023-01-25T06:50:59.355143Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 156
2023-01-25T06:50:59.355146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::156
2023-01-25T06:50:59.355148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.355150Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.355152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [23, 174, 67, 191, 185, 130, 26, 246, 195, 208, 54, 109, 208, 253, 244, 209, 165, 46, 35, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 48, 151, 243, 120, 89, 27, 129, 230, 249, 182, 62, 246, 236, 88, 132, 133, 35, 11, 98]) }
2023-01-25T06:50:59.355798Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15495545,
    events_root: None,
}
2023-01-25T06:50:59.355819Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 157
2023-01-25T06:50:59.355821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::157
2023-01-25T06:50:59.355824Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.355826Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.355828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [234, 110, 16, 153, 38, 6, 218, 156, 122, 169, 121, 26, 254, 151, 59, 149, 82, 243, 17, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([225, 90, 38, 122, 66, 192, 22, 132, 157, 186, 48, 208, 20, 183, 225, 129, 28, 153, 191, 143]) }
2023-01-25T06:50:59.356462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14991821,
    events_root: None,
}
2023-01-25T06:50:59.356483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 158
2023-01-25T06:50:59.356486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::158
2023-01-25T06:50:59.356488Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.356490Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.356492Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [22, 125, 25, 15, 118, 29, 85, 29, 170, 92, 159, 38, 55, 200, 77, 68, 234, 104, 167, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([207, 106, 230, 36, 128, 3, 64, 97, 112, 155, 53, 242, 49, 58, 211, 183, 163, 130, 183, 38]) }
2023-01-25T06:50:59.357191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15408911,
    events_root: None,
}
2023-01-25T06:50:59.357212Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 159
2023-01-25T06:50:59.357215Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::159
2023-01-25T06:50:59.357217Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.357219Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.357221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [196, 99, 207, 162, 98, 3, 238, 208, 156, 239, 251, 137, 251, 171, 111, 130, 62, 213, 18, 231, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([160, 235, 122, 2, 215, 254, 201, 155, 119, 78, 235, 192, 60, 113, 223, 58, 1, 185, 60, 85]) }
2023-01-25T06:50:59.357886Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16074103,
    events_root: None,
}
2023-01-25T06:50:59.357908Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 160
2023-01-25T06:50:59.357911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::160
2023-01-25T06:50:59.357913Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.357917Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.357919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [197, 146, 5, 66, 155, 102, 93, 206, 66, 119, 48, 227, 249, 60, 229, 162, 77, 34, 180, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([52, 213, 157, 186, 11, 97, 223, 186, 141, 145, 5, 181, 198, 184, 50, 254, 105, 198, 22, 17]) }
2023-01-25T06:50:59.358633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16898325,
    events_root: None,
}
2023-01-25T06:50:59.358656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 161
2023-01-25T06:50:59.358659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::161
2023-01-25T06:50:59.358661Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.358664Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.358665Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [219, 194, 196, 194, 99, 99, 64, 121, 73, 125, 109, 149, 141, 193, 236, 104, 141, 110, 254, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 49, 230, 26, 61, 225, 100, 172, 133, 175, 68, 18, 123, 99, 123, 35, 106, 40, 238, 75]) }
2023-01-25T06:50:59.359322Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16175365,
    events_root: None,
}
2023-01-25T06:50:59.359344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 162
2023-01-25T06:50:59.359347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::162
2023-01-25T06:50:59.359349Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.359351Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.359353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [231, 80, 138, 74, 165, 2, 81, 24, 189, 31, 249, 159, 201, 152, 77, 61, 60, 61, 248, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([182, 6, 185, 18, 133, 16, 215, 245, 36, 217, 66, 177, 231, 21, 254, 217, 58, 11, 229, 93]) }
2023-01-25T06:50:59.359930Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13742549,
    events_root: None,
}
2023-01-25T06:50:59.359948Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 163
2023-01-25T06:50:59.359950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::163
2023-01-25T06:50:59.359952Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.359955Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.359956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [152, 57, 207, 122, 225, 208, 14, 193, 222, 39, 89, 17, 170, 77, 168, 251, 176, 243, 6, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 124, 11, 203, 117, 104, 178, 126, 106, 103, 144, 179, 101, 101, 249, 198, 8, 24, 120, 106]) }
2023-01-25T06:50:59.360667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15309843,
    events_root: None,
}
2023-01-25T06:50:59.360689Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 164
2023-01-25T06:50:59.360692Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::164
2023-01-25T06:50:59.360693Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.360697Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.360699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [239, 219, 87, 208, 106, 139, 214, 152, 190, 61, 169, 165, 20, 95, 87, 111, 243, 85, 60, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([158, 244, 122, 14, 138, 53, 31, 2, 77, 188, 36, 151, 210, 57, 189, 97, 56, 70, 38, 8]) }
2023-01-25T06:50:59.361341Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15179757,
    events_root: None,
}
2023-01-25T06:50:59.361364Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 165
2023-01-25T06:50:59.361367Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::165
2023-01-25T06:50:59.361369Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.361372Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.361373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [46, 52, 214, 248, 54, 191, 116, 81, 176, 209, 132, 27, 101, 5, 137, 204, 147, 170, 115, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([129, 159, 66, 60, 246, 4, 104, 99, 223, 43, 143, 209, 74, 199, 65, 71, 140, 231, 24, 26]) }
2023-01-25T06:50:59.362054Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16830351,
    events_root: None,
}
2023-01-25T06:50:59.362077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 166
2023-01-25T06:50:59.362079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::166
2023-01-25T06:50:59.362082Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.362084Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.362086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [25, 121, 197, 141, 38, 95, 79, 42, 227, 211, 168, 110, 197, 21, 108, 231, 252, 0, 106, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 65, 156, 7, 131, 113, 102, 22, 42, 60, 154, 16, 44, 92, 72, 50, 166, 65, 206, 71]) }
2023-01-25T06:50:59.362752Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16447113,
    events_root: None,
}
2023-01-25T06:50:59.362773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 167
2023-01-25T06:50:59.362776Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "clearReturnBuffer"::Merge::167
2023-01-25T06:50:59.362778Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/clearReturnBuffer.json"
2023-01-25T06:50:59.362781Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-25T06:50:59.362783Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 4, 135, 208, 216, 93, 184, 27, 204, 200, 181, 216, 13, 114, 33, 118, 133, 167, 76, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([134, 70, 73, 170, 33, 5, 210, 145, 113, 224, 8, 209, 199, 155, 193, 121, 145, 6, 60, 206]) }
2023-01-25T06:50:59.363468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17036335,
    events_root: None,
}
2023-01-25T06:50:59.365510Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:811.38591ms
2023-01-25T06:50:59.633835Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/create_callprecompile_returndatasize.json", Total Files :: 1
2023-01-25T06:50:59.663704Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:50:59.663947Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:59.663952Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:50:59.664009Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:59.664012Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:50:59.664077Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:50:59.664154Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:50:59.664158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create_callprecompile_returndatasize"::Istanbul::0
2023-01-25T06:50:59.664162Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/create_callprecompile_returndatasize.json"
2023-01-25T06:50:59.664167Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:50:59.664169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 36864, value: 0 }
	input: 0000000000000000000000000000000000000000000000000000000000112233
2023-01-25T06:51:00.313696Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13562643,
    events_root: None,
}
2023-01-25T06:51:00.313737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:00.313744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create_callprecompile_returndatasize"::Berlin::0
2023-01-25T06:51:00.313747Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/create_callprecompile_returndatasize.json"
2023-01-25T06:51:00.313751Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:00.313753Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 204, 229, 246, 5, 48, 39, 94, 233, 49, 140, 225, 239, 249, 228, 191, 238, 129, 1, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 36864, value: 0 }
	input: 0000000000000000000000000000000000000000000000000000000000112233
2023-01-25T06:51:00.314489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13764248,
    events_root: None,
}
2023-01-25T06:51:00.314510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:00.314514Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create_callprecompile_returndatasize"::London::0
2023-01-25T06:51:00.314516Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/create_callprecompile_returndatasize.json"
2023-01-25T06:51:00.314519Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:00.314520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 206, 105, 18, 180, 86, 169, 134, 66, 145, 242, 213, 71, 127, 184, 201, 186, 98, 26, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 36864, value: 0 }
	input: 0000000000000000000000000000000000000000000000000000000000112233
2023-01-25T06:51:00.315183Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13592147,
    events_root: None,
}
2023-01-25T06:51:00.315201Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:00.315205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create_callprecompile_returndatasize"::Merge::0
2023-01-25T06:51:00.315207Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/create_callprecompile_returndatasize.json"
2023-01-25T06:51:00.315210Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:00.315212Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 146, 186, 46, 153, 226, 84, 67, 25, 239, 102, 183, 123, 143, 110, 42, 204, 247, 6, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 36864, value: 0 }
	input: 0000000000000000000000000000000000000000000000000000000000112233
2023-01-25T06:51:00.315879Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13729399,
    events_root: None,
}
2023-01-25T06:51:00.318633Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:652.212702ms
2023-01-25T06:51:00.589229Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json", Total Files :: 1
2023-01-25T06:51:00.647145Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:00.647333Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:00.647336Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:00.647390Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:00.647460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:00.647463Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Istanbul::0
2023-01-25T06:51:00.647466Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:00.647469Z  INFO evm_eth_compliance::statetest::runner: TX len : 98
2023-01-25T06:51:00.647470Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.079200Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565564,
    events_root: None,
}
2023-01-25T06:51:01.079218Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.079232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-25T06:51:01.079239Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Istanbul::1
2023-01-25T06:51:01.079241Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.079244Z  INFO evm_eth_compliance::statetest::runner: TX len : 99
2023-01-25T06:51:01.079245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.079379Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565565,
    events_root: None,
}
2023-01-25T06:51:01.079384Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.079393Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-25T06:51:01.079395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Istanbul::2
2023-01-25T06:51:01.079397Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.079400Z  INFO evm_eth_compliance::statetest::runner: TX len : 246
2023-01-25T06:51:01.079401Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.079491Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1566952,
    events_root: None,
}
2023-01-25T06:51:01.079496Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.079505Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-25T06:51:01.079508Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Istanbul::3
2023-01-25T06:51:01.079509Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.079512Z  INFO evm_eth_compliance::statetest::runner: TX len : 480
2023-01-25T06:51:01.079513Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.079601Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1567561,
    events_root: None,
}
2023-01-25T06:51:01.079608Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.079616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-25T06:51:01.079618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Istanbul::4
2023-01-25T06:51:01.079620Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.079623Z  INFO evm_eth_compliance::statetest::runner: TX len : 99
2023-01-25T06:51:01.079625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.079712Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565565,
    events_root: None,
}
2023-01-25T06:51:01.079716Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.079726Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:01.079728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Berlin::0
2023-01-25T06:51:01.079730Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.079733Z  INFO evm_eth_compliance::statetest::runner: TX len : 98
2023-01-25T06:51:01.079734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.079821Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565564,
    events_root: None,
}
2023-01-25T06:51:01.079825Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.079833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-25T06:51:01.079836Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Berlin::1
2023-01-25T06:51:01.079837Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.079840Z  INFO evm_eth_compliance::statetest::runner: TX len : 99
2023-01-25T06:51:01.079841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.079935Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565565,
    events_root: None,
}
2023-01-25T06:51:01.079941Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.079949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-25T06:51:01.079951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Berlin::2
2023-01-25T06:51:01.079953Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.079956Z  INFO evm_eth_compliance::statetest::runner: TX len : 246
2023-01-25T06:51:01.079957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.080045Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1566952,
    events_root: None,
}
2023-01-25T06:51:01.080050Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.080058Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-25T06:51:01.080060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Berlin::3
2023-01-25T06:51:01.080062Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.080065Z  INFO evm_eth_compliance::statetest::runner: TX len : 480
2023-01-25T06:51:01.080066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.080154Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1567561,
    events_root: None,
}
2023-01-25T06:51:01.080158Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.080166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-25T06:51:01.080168Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Berlin::4
2023-01-25T06:51:01.080171Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.080173Z  INFO evm_eth_compliance::statetest::runner: TX len : 99
2023-01-25T06:51:01.080175Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.080262Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565565,
    events_root: None,
}
2023-01-25T06:51:01.080266Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.080276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:01.080278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::London::0
2023-01-25T06:51:01.080280Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.080283Z  INFO evm_eth_compliance::statetest::runner: TX len : 98
2023-01-25T06:51:01.080284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.080370Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565564,
    events_root: None,
}
2023-01-25T06:51:01.080374Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.080384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T06:51:01.080386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::London::1
2023-01-25T06:51:01.080388Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.080390Z  INFO evm_eth_compliance::statetest::runner: TX len : 99
2023-01-25T06:51:01.080392Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.080478Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565565,
    events_root: None,
}
2023-01-25T06:51:01.080482Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.080490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-25T06:51:01.080493Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::London::2
2023-01-25T06:51:01.080494Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.080497Z  INFO evm_eth_compliance::statetest::runner: TX len : 246
2023-01-25T06:51:01.080498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.080585Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1566952,
    events_root: None,
}
2023-01-25T06:51:01.080589Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.080597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-25T06:51:01.080600Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::London::3
2023-01-25T06:51:01.080602Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.080604Z  INFO evm_eth_compliance::statetest::runner: TX len : 480
2023-01-25T06:51:01.080606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.080709Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1567561,
    events_root: None,
}
2023-01-25T06:51:01.080714Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.080723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-25T06:51:01.080725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::London::4
2023-01-25T06:51:01.080727Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.080729Z  INFO evm_eth_compliance::statetest::runner: TX len : 99
2023-01-25T06:51:01.080731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.080819Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565565,
    events_root: None,
}
2023-01-25T06:51:01.080825Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.080833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:01.080836Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Merge::0
2023-01-25T06:51:01.080838Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.080840Z  INFO evm_eth_compliance::statetest::runner: TX len : 98
2023-01-25T06:51:01.080841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.080933Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565564,
    events_root: None,
}
2023-01-25T06:51:01.080937Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.080949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T06:51:01.080951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Merge::1
2023-01-25T06:51:01.080953Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.080956Z  INFO evm_eth_compliance::statetest::runner: TX len : 99
2023-01-25T06:51:01.080957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.081043Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565565,
    events_root: None,
}
2023-01-25T06:51:01.081048Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.081056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-25T06:51:01.081059Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Merge::2
2023-01-25T06:51:01.081060Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.081064Z  INFO evm_eth_compliance::statetest::runner: TX len : 246
2023-01-25T06:51:01.081065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.081152Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1566952,
    events_root: None,
}
2023-01-25T06:51:01.081156Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.081164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-25T06:51:01.081167Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Merge::3
2023-01-25T06:51:01.081169Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.081172Z  INFO evm_eth_compliance::statetest::runner: TX len : 480
2023-01-25T06:51:01.081174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.081261Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1567561,
    events_root: None,
}
2023-01-25T06:51:01.081265Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.081274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-25T06:51:01.081276Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modexp_modsize0_returndatasize"::Merge::4
2023-01-25T06:51:01.081278Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json"
2023-01-25T06:51:01.081280Z  INFO evm_eth_compliance::statetest::runner: TX len : 99
2023-01-25T06:51:01.081282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:01.081368Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1565565,
    events_root: None,
}
2023-01-25T06:51:01.081373Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=19): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:01.083018Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:434.241779ms
2023-01-25T06:51:01.365109Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_0_0_following_successful_create.json", Total Files :: 1
2023-01-25T06:51:01.425319Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:01.425523Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:01.425527Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:01.425582Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:01.425654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:01.425657Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_0_0_following_successful_create"::Istanbul::0
2023-01-25T06:51:01.425661Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_0_0_following_successful_create.json"
2023-01-25T06:51:01.425665Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:01.425666Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-25T06:51:02.100063Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13365543,
    events_root: None,
}
2023-01-25T06:51:02.100096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:02.100103Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_0_0_following_successful_create"::Berlin::0
2023-01-25T06:51:02.100106Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_0_0_following_successful_create.json"
2023-01-25T06:51:02.100109Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:02.100110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 204, 229, 246, 5, 48, 39, 94, 233, 49, 140, 225, 239, 249, 228, 191, 238, 129, 1, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-25T06:51:02.100738Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13567148,
    events_root: None,
}
2023-01-25T06:51:02.100757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:02.100760Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_0_0_following_successful_create"::London::0
2023-01-25T06:51:02.100762Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_0_0_following_successful_create.json"
2023-01-25T06:51:02.100765Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:02.100766Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 206, 105, 18, 180, 86, 169, 134, 66, 145, 242, 213, 71, 127, 184, 201, 186, 98, 26, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-25T06:51:02.101299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13395047,
    events_root: None,
}
2023-01-25T06:51:02.101317Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:02.101320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_0_0_following_successful_create"::Merge::0
2023-01-25T06:51:02.101322Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_0_0_following_successful_create.json"
2023-01-25T06:51:02.101325Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:02.101326Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 146, 186, 46, 153, 226, 84, 67, 25, 239, 102, 183, 123, 143, 110, 42, 204, 247, 6, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-25T06:51:02.101867Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13532299,
    events_root: None,
}
2023-01-25T06:51:02.103633Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:676.57136ms
2023-01-25T06:51:02.377816Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_afterFailing_create.json", Total Files :: 1
2023-01-25T06:51:02.408264Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:02.408485Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:02.408490Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:02.408565Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:02.408668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:02.408675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_afterFailing_create"::Istanbul::0
2023-01-25T06:51:02.408679Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_afterFailing_create.json"
2023-01-25T06:51:02.408684Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:02.408686Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-25T06:51:03.053809Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 12161671,
    events_root: None,
}
2023-01-25T06:51:03.053823Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 1,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor reverted",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor failed: send to f0403 method 1 aborted with code 33",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "send to f01 method 3 aborted with code 33",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=32): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:03.053863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:03.053871Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_afterFailing_create"::Berlin::0
2023-01-25T06:51:03.053874Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_afterFailing_create.json"
2023-01-25T06:51:03.053877Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:03.053879Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-25T06:51:03.054537Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 12422750,
    events_root: None,
}
2023-01-25T06:51:03.054545Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 1,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor reverted",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor failed: send to f0403 method 1 aborted with code 33",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "send to f01 method 3 aborted with code 33",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=32): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:03.054575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:03.054579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_afterFailing_create"::London::0
2023-01-25T06:51:03.054581Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_afterFailing_create.json"
2023-01-25T06:51:03.054584Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:03.054585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-25T06:51:03.055111Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 11105444,
    events_root: None,
}
2023-01-25T06:51:03.055117Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 1,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor reverted",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor failed: send to f0403 method 1 aborted with code 33",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "send to f01 method 3 aborted with code 33",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=32): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:03.055142Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:03.055145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_afterFailing_create"::Merge::0
2023-01-25T06:51:03.055147Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_afterFailing_create.json"
2023-01-25T06:51:03.055150Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:03.055151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-25T06:51:03.055688Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 12332833,
    events_root: None,
}
2023-01-25T06:51:03.055694Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 1,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor reverted",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor failed: send to f0403 method 1 aborted with code 33",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "send to f01 method 3 aborted with code 33",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=32): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:03.057685Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:647.464963ms
2023-01-25T06:51:03.341424Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_callcode.json", Total Files :: 1
2023-01-25T06:51:03.377610Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:03.377834Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:03.377839Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:03.377894Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:03.377896Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:03.377957Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:03.377959Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:03.378016Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:03.378089Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:03.378094Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_callcode"::Istanbul::0
2023-01-25T06:51:03.378097Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_callcode.json"
2023-01-25T06:51:03.378100Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:03.378101Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:03.746818Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544529,
    events_root: None,
}
2023-01-25T06:51:03.746836Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=33): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:03.746850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:03.746857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_callcode"::Berlin::0
2023-01-25T06:51:03.746860Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_callcode.json"
2023-01-25T06:51:03.746863Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:03.746866Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:03.746984Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544529,
    events_root: None,
}
2023-01-25T06:51:03.746989Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=33): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:03.746999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:03.747003Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_callcode"::London::0
2023-01-25T06:51:03.747005Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_callcode.json"
2023-01-25T06:51:03.747008Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:03.747009Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:03.747096Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544529,
    events_root: None,
}
2023-01-25T06:51:03.747100Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=33): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:03.747109Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:03.747111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_callcode"::Merge::0
2023-01-25T06:51:03.747114Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_callcode.json"
2023-01-25T06:51:03.747117Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:03.747118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:03.747204Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544529,
    events_root: None,
}
2023-01-25T06:51:03.747209Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=33): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:03.748603Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:369.613597ms
2023-01-25T06:51:04.027580Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_delegatecall.json", Total Files :: 1
2023-01-25T06:51:04.057370Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:04.057569Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:04.057572Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:04.057627Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:04.057629Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:04.057687Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:04.057690Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:04.057747Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:04.057818Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:04.057822Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_delegatecall"::Istanbul::0
2023-01-25T06:51:04.057825Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_delegatecall.json"
2023-01-25T06:51:04.057828Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:04.057830Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:04.426326Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-25T06:51:04.426349Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:04.426357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_delegatecall"::Berlin::0
2023-01-25T06:51:04.426360Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_delegatecall.json"
2023-01-25T06:51:04.426363Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:04.426364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:04.426460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-25T06:51:04.426466Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:04.426468Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_delegatecall"::London::0
2023-01-25T06:51:04.426471Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_delegatecall.json"
2023-01-25T06:51:04.426473Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:04.426475Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:04.426551Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-25T06:51:04.426557Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:04.426559Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_delegatecall"::Merge::0
2023-01-25T06:51:04.426561Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_delegatecall.json"
2023-01-25T06:51:04.426565Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:04.426567Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:04.426640Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-25T06:51:04.428298Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:369.279249ms
2023-01-25T06:51:04.717906Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_staticcall.json", Total Files :: 1
2023-01-25T06:51:04.746839Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:04.747028Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:04.747032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:04.747083Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:04.747086Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:04.747147Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:04.747149Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:04.747205Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:04.747274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:04.747277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_staticcall"::Istanbul::0
2023-01-25T06:51:04.747280Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_staticcall.json"
2023-01-25T06:51:04.747283Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:04.747285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:05.110164Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1725895,
    events_root: None,
}
2023-01-25T06:51:05.110182Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=39): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:05.110200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:05.110208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_staticcall"::Berlin::0
2023-01-25T06:51:05.110211Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_staticcall.json"
2023-01-25T06:51:05.110214Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:05.110216Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:05.110375Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1725895,
    events_root: None,
}
2023-01-25T06:51:05.110381Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=39): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:05.110394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:05.110398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_staticcall"::London::0
2023-01-25T06:51:05.110402Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_staticcall.json"
2023-01-25T06:51:05.110406Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:05.110409Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:05.110531Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1725895,
    events_root: None,
}
2023-01-25T06:51:05.110537Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=39): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:05.110550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:05.110554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_failing_staticcall"::Merge::0
2023-01-25T06:51:05.110557Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_staticcall.json"
2023-01-25T06:51:05.110561Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:05.110563Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:05.110682Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1725895,
    events_root: None,
}
2023-01-25T06:51:05.110688Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=39): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:05.112858Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.866727ms
2023-01-25T06:51:05.397162Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_revert_in_staticcall.json", Total Files :: 1
2023-01-25T06:51:05.435555Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:05.435750Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:05.435753Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:05.435809Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:05.435811Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:05.435872Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:05.435874Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:05.435939Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:05.436013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:05.436017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_revert_in_staticcall"::Istanbul::0
2023-01-25T06:51:05.436021Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_revert_in_staticcall.json"
2023-01-25T06:51:05.436024Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:05.436025Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:05.806053Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1785717,
    events_root: None,
}
2023-01-25T06:51:05.806072Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:05.806093Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:05.806101Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_revert_in_staticcall"::Berlin::0
2023-01-25T06:51:05.806104Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_revert_in_staticcall.json"
2023-01-25T06:51:05.806108Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:05.806110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:05.806255Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1785717,
    events_root: None,
}
2023-01-25T06:51:05.806261Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:05.806279Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:05.806283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_revert_in_staticcall"::London::0
2023-01-25T06:51:05.806286Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_revert_in_staticcall.json"
2023-01-25T06:51:05.806289Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:05.806291Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:05.806410Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1785717,
    events_root: None,
}
2023-01-25T06:51:05.806416Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:05.806432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:05.806435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_revert_in_staticcall"::Merge::0
2023-01-25T06:51:05.806438Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_revert_in_staticcall.json"
2023-01-25T06:51:05.806442Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:05.806444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:05.806579Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1785717,
    events_root: None,
}
2023-01-25T06:51:05.806585Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:05.808007Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.051123ms
2023-01-25T06:51:06.061737Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_callcode.json", Total Files :: 1
2023-01-25T06:51:06.091801Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:06.092058Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:06.092063Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:06.092118Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:06.092120Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:06.092204Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:06.092303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:06.092308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_callcode"::Istanbul::0
2023-01-25T06:51:06.092311Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_callcode.json"
2023-01-25T06:51:06.092315Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:06.092318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:06.483977Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544627,
    events_root: None,
}
2023-01-25T06:51:06.483997Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=34): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:06.484014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:06.484023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_callcode"::Berlin::0
2023-01-25T06:51:06.484026Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_callcode.json"
2023-01-25T06:51:06.484029Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:06.484031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:06.484178Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544627,
    events_root: None,
}
2023-01-25T06:51:06.484185Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=34): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:06.484196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:06.484199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_callcode"::London::0
2023-01-25T06:51:06.484202Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_callcode.json"
2023-01-25T06:51:06.484206Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:06.484208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:06.484310Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544627,
    events_root: None,
}
2023-01-25T06:51:06.484315Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=34): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:06.484323Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:06.484326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_callcode"::Merge::0
2023-01-25T06:51:06.484328Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_callcode.json"
2023-01-25T06:51:06.484331Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:06.484332Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:06.484424Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544627,
    events_root: None,
}
2023-01-25T06:51:06.484428Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=34): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:06.485920Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:392.64057ms
2023-01-25T06:51:06.742524Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_delegatecall.json", Total Files :: 1
2023-01-25T06:51:06.804895Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:06.805091Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:06.805094Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:06.805150Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:06.805152Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:06.805216Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:06.805289Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:06.805293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_delegatecall"::Istanbul::0
2023-01-25T06:51:06.805296Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_delegatecall.json"
2023-01-25T06:51:06.805299Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:06.805301Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:07.169116Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2672405,
    events_root: None,
}
2023-01-25T06:51:07.169132Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:07.169152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:07.169158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_delegatecall"::Berlin::0
2023-01-25T06:51:07.169160Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_delegatecall.json"
2023-01-25T06:51:07.169163Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:07.169164Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:07.169357Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2672405,
    events_root: None,
}
2023-01-25T06:51:07.169363Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:07.169376Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:07.169379Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_delegatecall"::London::0
2023-01-25T06:51:07.169382Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_delegatecall.json"
2023-01-25T06:51:07.169385Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:07.169386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:07.169565Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2672405,
    events_root: None,
}
2023-01-25T06:51:07.169571Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:07.169584Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:07.169586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_delegatecall"::Merge::0
2023-01-25T06:51:07.169588Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_delegatecall.json"
2023-01-25T06:51:07.169591Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:07.169593Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:07.169769Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2672405,
    events_root: None,
}
2023-01-25T06:51:07.169775Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:07.171332Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.899772ms
2023-01-25T06:51:07.447923Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_staticcall.json", Total Files :: 1
2023-01-25T06:51:07.480571Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:07.480765Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:07.480769Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:07.480823Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:07.480824Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:07.480883Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:07.480885Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:07.480940Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:07.481013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:07.481017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_staticcall"::Istanbul::0
2023-01-25T06:51:07.481020Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_staticcall.json"
2023-01-25T06:51:07.481023Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:07.481024Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:07.820516Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1785717,
    events_root: None,
}
2023-01-25T06:51:07.820535Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:07.820552Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:07.820558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_staticcall"::Berlin::0
2023-01-25T06:51:07.820560Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_staticcall.json"
2023-01-25T06:51:07.820563Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:07.820565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:07.820688Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1785717,
    events_root: None,
}
2023-01-25T06:51:07.820693Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:07.820706Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:07.820709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_staticcall"::London::0
2023-01-25T06:51:07.820710Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_staticcall.json"
2023-01-25T06:51:07.820713Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:07.820715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:07.820819Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1785717,
    events_root: None,
}
2023-01-25T06:51:07.820824Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:07.820837Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:07.820839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_after_successful_staticcall"::Merge::0
2023-01-25T06:51:07.820841Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_successful_staticcall.json"
2023-01-25T06:51:07.820844Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:07.820845Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:07.820967Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1785717,
    events_root: None,
}
2023-01-25T06:51:07.820972Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=40): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:07.822137Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:340.417824ms
2023-01-25T06:51:08.100273Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_call.json", Total Files :: 1
2023-01-25T06:51:08.130139Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:08.130338Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:08.130341Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:08.130391Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:08.130393Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:08.130455Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:08.130524Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:08.130527Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_call"::Istanbul::0
2023-01-25T06:51:08.130530Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_call.json"
2023-01-25T06:51:08.130534Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:08.130535Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:08.535798Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4019726,
    events_root: None,
}
2023-01-25T06:51:08.535821Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:08.535827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_call"::Berlin::0
2023-01-25T06:51:08.535830Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_call.json"
2023-01-25T06:51:08.535834Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:08.535835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:08.536046Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3079804,
    events_root: None,
}
2023-01-25T06:51:08.536056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:08.536058Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_call"::London::0
2023-01-25T06:51:08.536061Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_call.json"
2023-01-25T06:51:08.536063Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:08.536065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:08.536247Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3079804,
    events_root: None,
}
2023-01-25T06:51:08.536256Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:08.536260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_call"::Merge::0
2023-01-25T06:51:08.536262Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_call.json"
2023-01-25T06:51:08.536264Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:08.536265Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:08.536446Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3079804,
    events_root: None,
}
2023-01-25T06:51:08.537806Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:406.321168ms
2023-01-25T06:51:08.811664Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_create.json", Total Files :: 1
2023-01-25T06:51:08.841484Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:08.841690Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:08.841694Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:08.841746Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:08.841748Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:08.841809Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:08.841880Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:08.841883Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_create"::Istanbul::0
2023-01-25T06:51:08.841885Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_create.json"
2023-01-25T06:51:08.841888Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:08.841890Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-25T06:51:09.467822Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 13355739,
    events_root: None,
}
2023-01-25T06:51:09.467836Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:09.467863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:09.467869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_create"::Berlin::0
2023-01-25T06:51:09.467871Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_create.json"
2023-01-25T06:51:09.467875Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:09.467876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-25T06:51:09.468491Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 13616818,
    events_root: None,
}
2023-01-25T06:51:09.468498Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:09.468519Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:09.468522Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_create"::London::0
2023-01-25T06:51:09.468524Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_create.json"
2023-01-25T06:51:09.468527Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:09.468528Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-25T06:51:09.469020Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 12299512,
    events_root: None,
}
2023-01-25T06:51:09.469026Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:09.469045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:09.469047Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_create"::Merge::0
2023-01-25T06:51:09.469049Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_create.json"
2023-01-25T06:51:09.469052Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:09.469053Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-25T06:51:09.469566Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 13526901,
    events_root: None,
}
2023-01-25T06:51:09.469573Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:09.471541Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:628.113736ms
2023-01-25T06:51:09.729641Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_failing_call.json", Total Files :: 1
2023-01-25T06:51:09.760479Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:09.760730Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:09.760735Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:09.760791Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:09.760793Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:09.760857Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:09.760936Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:09.760939Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_failing_call"::Istanbul::0
2023-01-25T06:51:09.760942Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_failing_call.json"
2023-01-25T06:51:09.760946Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:09.760948Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:10.115596Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3061636,
    events_root: None,
}
2023-01-25T06:51:10.115613Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 36,
                    },
                    message: "ABORT(pc=0): stack underflow",
                },
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=45): returndatacopy start 1 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:10.115631Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:10.115637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_failing_call"::Berlin::0
2023-01-25T06:51:10.115639Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_failing_call.json"
2023-01-25T06:51:10.115642Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:10.115643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:10.115857Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3061636,
    events_root: None,
}
2023-01-25T06:51:10.115864Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 36,
                    },
                    message: "ABORT(pc=0): stack underflow",
                },
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=45): returndatacopy start 1 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:10.115878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:10.115881Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_failing_call"::London::0
2023-01-25T06:51:10.115883Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_failing_call.json"
2023-01-25T06:51:10.115886Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:10.115887Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:10.116077Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3061636,
    events_root: None,
}
2023-01-25T06:51:10.116082Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 36,
                    },
                    message: "ABORT(pc=0): stack underflow",
                },
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=45): returndatacopy start 1 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:10.116097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:10.116099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_failing_call"::Merge::0
2023-01-25T06:51:10.116101Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_failing_call.json"
2023-01-25T06:51:10.116104Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:10.116106Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:10.116278Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3061636,
    events_root: None,
}
2023-01-25T06:51:10.116284Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 36,
                    },
                    message: "ABORT(pc=0): stack underflow",
                },
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=45): returndatacopy start 1 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:10.117844Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.823308ms
2023-01-25T06:51:10.402424Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert.json", Total Files :: 1
2023-01-25T06:51:10.432156Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:10.432359Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:10.432362Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:10.432414Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:10.432417Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:10.432478Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:10.432548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:10.432553Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_revert"::Istanbul::0
2023-01-25T06:51:10.432556Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert.json"
2023-01-25T06:51:10.432559Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:10.432561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:10.787041Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4055690,
    events_root: None,
}
2023-01-25T06:51:10.787065Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:10.787072Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_revert"::Berlin::0
2023-01-25T06:51:10.787075Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert.json"
2023-01-25T06:51:10.787078Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:10.787080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:10.787284Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3112204,
    events_root: None,
}
2023-01-25T06:51:10.787294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:10.787297Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_revert"::London::0
2023-01-25T06:51:10.787299Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert.json"
2023-01-25T06:51:10.787301Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:10.787303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:10.787484Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3112204,
    events_root: None,
}
2023-01-25T06:51:10.787493Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:10.787496Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_revert"::Merge::0
2023-01-25T06:51:10.787498Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert.json"
2023-01-25T06:51:10.787501Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:10.787503Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:10.787685Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3112204,
    events_root: None,
}
2023-01-25T06:51:10.789132Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.543332ms
2023-01-25T06:51:11.064851Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert_in_create.json", Total Files :: 1
2023-01-25T06:51:11.094291Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:11.094484Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:11.094488Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:11.094543Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:11.094613Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:11.094617Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_revert_in_create"::Istanbul::0
2023-01-25T06:51:11.094620Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert_in_create.json"
2023-01-25T06:51:11.094623Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:11.094625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-25T06:51:11.744890Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 12168821,
    events_root: None,
}
2023-01-25T06:51:11.744902Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 1,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor reverted",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor failed: send to f0403 method 1 aborted with code 33",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "send to f01 method 3 aborted with code 33",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=20): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:11.744940Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:11.744946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_revert_in_create"::Berlin::0
2023-01-25T06:51:11.744949Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert_in_create.json"
2023-01-25T06:51:11.744952Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:11.744953Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-25T06:51:11.745566Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 12429900,
    events_root: None,
}
2023-01-25T06:51:11.745572Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 1,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor reverted",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor failed: send to f0403 method 1 aborted with code 33",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "send to f01 method 3 aborted with code 33",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=20): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:11.745602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:11.745605Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_revert_in_create"::London::0
2023-01-25T06:51:11.745607Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert_in_create.json"
2023-01-25T06:51:11.745610Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:11.745611Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-25T06:51:11.746106Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 11112594,
    events_root: None,
}
2023-01-25T06:51:11.746112Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 1,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor reverted",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor failed: send to f0403 method 1 aborted with code 33",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "send to f01 method 3 aborted with code 33",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=20): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:11.746142Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:11.746144Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_revert_in_create"::Merge::0
2023-01-25T06:51:11.746147Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_revert_in_create.json"
2023-01-25T06:51:11.746149Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:11.746151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-25T06:51:11.746670Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 12339983,
    events_root: None,
}
2023-01-25T06:51:11.746678Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 1,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor reverted",
                },
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "constructor failed: send to f0403 method 1 aborted with code 33",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "send to f01 method 3 aborted with code 33",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=20): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:11.748554Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:652.420025ms
2023-01-25T06:51:12.031594Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_successful_create.json", Total Files :: 1
2023-01-25T06:51:12.060961Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:12.061169Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:12.061174Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:12.061229Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:12.061301Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:12.061304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_successful_create"::Istanbul::0
2023-01-25T06:51:12.061307Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_successful_create.json"
2023-01-25T06:51:12.061311Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:12.061312Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-25T06:51:12.757817Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 13355603,
    events_root: None,
}
2023-01-25T06:51:12.757829Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): returndatacopy start 1 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:12.757860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:12.757866Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_successful_create"::Berlin::0
2023-01-25T06:51:12.757868Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_successful_create.json"
2023-01-25T06:51:12.757871Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:12.757873Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-25T06:51:12.758484Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 13616682,
    events_root: None,
}
2023-01-25T06:51:12.758490Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): returndatacopy start 1 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:12.758510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:12.758513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_successful_create"::London::0
2023-01-25T06:51:12.758516Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_successful_create.json"
2023-01-25T06:51:12.758518Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:12.758520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-25T06:51:12.759016Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 12299376,
    events_root: None,
}
2023-01-25T06:51:12.759023Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): returndatacopy start 1 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:12.759042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:12.759045Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_successful_create"::Merge::0
2023-01-25T06:51:12.759047Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_successful_create.json"
2023-01-25T06:51:12.759050Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:12.759052Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-25T06:51:12.759574Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 13526765,
    events_root: None,
}
2023-01-25T06:51:12.759580Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): returndatacopy start 1 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:12.761257Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:698.644659ms
2023-01-25T06:51:13.038463Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_too_big_transfer.json", Total Files :: 1
2023-01-25T06:51:13.068680Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:13.068883Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:13.068887Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:13.068940Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:13.068942Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:13.069005Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:13.069078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:13.069081Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_too_big_transfer"::Istanbul::0
2023-01-25T06:51:13.069084Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_too_big_transfer.json"
2023-01-25T06:51:13.069088Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:13.069091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:13.452400Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1738690,
    events_root: None,
}
2023-01-25T06:51:13.452419Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=47): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: Some(
                Syscall {
                    module: "send",
                    function: "send",
                    error: InsufficientFunds,
                    message: "sender does not have funds to transfer (balance 0.0, transfer 0.00000000001)",
                },
            ),
        },
    ),
)
2023-01-25T06:51:13.452439Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:13.452445Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_too_big_transfer"::Berlin::0
2023-01-25T06:51:13.452447Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_too_big_transfer.json"
2023-01-25T06:51:13.452450Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:13.452452Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:13.452599Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1738690,
    events_root: None,
}
2023-01-25T06:51:13.452604Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=47): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: Some(
                Syscall {
                    module: "send",
                    function: "send",
                    error: InsufficientFunds,
                    message: "sender does not have funds to transfer (balance 0.0, transfer 0.00000000001)",
                },
            ),
        },
    ),
)
2023-01-25T06:51:13.452618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:13.452621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_too_big_transfer"::London::0
2023-01-25T06:51:13.452623Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_too_big_transfer.json"
2023-01-25T06:51:13.452625Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:13.452627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:13.452738Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1738690,
    events_root: None,
}
2023-01-25T06:51:13.452743Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=47): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: Some(
                Syscall {
                    module: "send",
                    function: "send",
                    error: InsufficientFunds,
                    message: "sender does not have funds to transfer (balance 0.0, transfer 0.00000000001)",
                },
            ),
        },
    ),
)
2023-01-25T06:51:13.452756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:13.452758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_following_too_big_transfer"::Merge::0
2023-01-25T06:51:13.452760Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_too_big_transfer.json"
2023-01-25T06:51:13.452763Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:13.452764Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:13.452875Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1738690,
    events_root: None,
}
2023-01-25T06:51:13.452880Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=47): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: Some(
                Syscall {
                    module: "send",
                    function: "send",
                    error: InsufficientFunds,
                    message: "sender does not have funds to transfer (balance 0.0, transfer 0.00000000001)",
                },
            ),
        },
    ),
)
2023-01-25T06:51:13.454445Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:384.216867ms
2023-01-25T06:51:13.727853Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial.json", Total Files :: 1
2023-01-25T06:51:13.758150Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:13.758344Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:13.758348Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:13.758404Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:13.758475Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:13.758479Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial"::Istanbul::0
2023-01-25T06:51:13.758482Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial.json"
2023-01-25T06:51:13.758485Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:13.758487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.099903Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1552251,
    events_root: None,
}
2023-01-25T06:51:14.099923Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=25): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.099938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:14.099945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial"::Berlin::0
2023-01-25T06:51:14.099947Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial.json"
2023-01-25T06:51:14.099950Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:14.099951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.100064Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1552251,
    events_root: None,
}
2023-01-25T06:51:14.100069Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=25): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.100079Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:14.100082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial"::London::0
2023-01-25T06:51:14.100084Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial.json"
2023-01-25T06:51:14.100086Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:14.100088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.100175Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1552251,
    events_root: None,
}
2023-01-25T06:51:14.100180Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=25): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.100189Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:14.100191Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial"::Merge::0
2023-01-25T06:51:14.100193Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial.json"
2023-01-25T06:51:14.100196Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:14.100197Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.100284Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1552251,
    events_root: None,
}
2023-01-25T06:51:14.100289Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=25): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.101762Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:342.15175ms
2023-01-25T06:51:14.375726Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json", Total Files :: 1
2023-01-25T06:51:14.404871Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:14.405065Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:14.405068Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:14.405122Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:14.405191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:14.405194Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::Istanbul::0
2023-01-25T06:51:14.405197Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.405200Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.405201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.770610Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.770628Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.770641Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-25T06:51:14.770648Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::Istanbul::1
2023-01-25T06:51:14.770650Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.770653Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.770654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.770755Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.770759Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.770768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-25T06:51:14.770770Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::Istanbul::2
2023-01-25T06:51:14.770772Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.770775Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.770776Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.770866Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.770871Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.770879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:14.770881Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::Berlin::0
2023-01-25T06:51:14.770883Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.770886Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.770887Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.770968Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.770972Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.770980Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-25T06:51:14.770983Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::Berlin::1
2023-01-25T06:51:14.770984Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.770987Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.770988Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.771068Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.771073Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.771081Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-25T06:51:14.771083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::Berlin::2
2023-01-25T06:51:14.771085Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.771088Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.771089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.771194Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.771200Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.771212Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:14.771216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::London::0
2023-01-25T06:51:14.771218Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.771222Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.771224Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.771331Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.771336Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.771344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T06:51:14.771347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::London::1
2023-01-25T06:51:14.771349Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.771352Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.771353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.771438Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.771442Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.771451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-25T06:51:14.771453Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::London::2
2023-01-25T06:51:14.771455Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.771457Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.771458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.771541Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.771545Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.771554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:14.771556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::Merge::0
2023-01-25T06:51:14.771558Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.771560Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.771562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.771644Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.771648Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.771656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T06:51:14.771659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::Merge::1
2023-01-25T06:51:14.771660Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.771663Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.771664Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.771747Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.771751Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.771761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-25T06:51:14.771764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_256"::Merge::2
2023-01-25T06:51:14.771767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
2023-01-25T06:51:14.771771Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T06:51:14.771773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:14.771888Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548708,
    events_root: None,
}
2023-01-25T06:51:14.771900Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=10): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:14.773174Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.046085ms
2023-01-25T06:51:15.036723Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_big_sum.json", Total Files :: 1
2023-01-25T06:51:15.066768Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:15.066966Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:15.066970Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:15.067026Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:15.067099Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:15.067103Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_big_sum"::Istanbul::0
2023-01-25T06:51:15.067106Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_big_sum.json"
2023-01-25T06:51:15.067109Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:15.067110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:15.438965Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1599662,
    events_root: None,
}
2023-01-25T06:51:15.438984Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:15.438999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:15.439007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_big_sum"::Berlin::0
2023-01-25T06:51:15.439009Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_big_sum.json"
2023-01-25T06:51:15.439012Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:15.439013Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:15.439136Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1599662,
    events_root: None,
}
2023-01-25T06:51:15.439142Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:15.439151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:15.439153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_big_sum"::London::0
2023-01-25T06:51:15.439155Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_big_sum.json"
2023-01-25T06:51:15.439158Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:15.439159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:15.439251Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1599662,
    events_root: None,
}
2023-01-25T06:51:15.439256Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:15.439264Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:15.439267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_initial_big_sum"::Merge::0
2023-01-25T06:51:15.439268Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_big_sum.json"
2023-01-25T06:51:15.439271Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:15.439272Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:15.439362Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1599662,
    events_root: None,
}
2023-01-25T06:51:15.439367Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=31): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:15.441031Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.614471ms
2023-01-25T06:51:15.725487Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_overrun.json", Total Files :: 1
2023-01-25T06:51:15.785756Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:15.786053Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:15.786061Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:15.786138Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:15.786143Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:15.786228Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:15.786333Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:15.786340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_overrun"::Istanbul::0
2023-01-25T06:51:15.786345Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_overrun.json"
2023-01-25T06:51:15.786349Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:15.786352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:16.159269Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3069333,
    events_root: None,
}
2023-01-25T06:51:16.159290Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=76): returndatacopy index exceeds max u32: integer overflow when casting to usize",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:16.159306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:16.159313Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_overrun"::Berlin::0
2023-01-25T06:51:16.159315Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_overrun.json"
2023-01-25T06:51:16.159317Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:16.159319Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:16.159515Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3069333,
    events_root: None,
}
2023-01-25T06:51:16.159521Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=76): returndatacopy index exceeds max u32: integer overflow when casting to usize",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:16.159534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:16.159536Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_overrun"::London::0
2023-01-25T06:51:16.159538Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_overrun.json"
2023-01-25T06:51:16.159541Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:16.159542Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:16.159726Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3069333,
    events_root: None,
}
2023-01-25T06:51:16.159732Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=76): returndatacopy index exceeds max u32: integer overflow when casting to usize",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:16.159743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:16.159746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopy_overrun"::Merge::0
2023-01-25T06:51:16.159748Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatacopy_overrun.json"
2023-01-25T06:51:16.159750Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:16.159752Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:16.159943Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3069333,
    events_root: None,
}
2023-01-25T06:51:16.159949Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=76): returndatacopy index exceeds max u32: integer overflow when casting to usize",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:16.161459Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.210604ms
2023-01-25T06:51:16.435250Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_callcode.json", Total Files :: 1
2023-01-25T06:51:16.495585Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:16.495774Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:16.495778Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:16.495831Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:16.495833Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:16.495891Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:16.495893Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:16.495958Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:16.496027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:16.496031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_callcode"::Istanbul::0
2023-01-25T06:51:16.496033Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_callcode.json"
2023-01-25T06:51:16.496037Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:16.496038Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:16.866778Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543776,
    events_root: None,
}
2023-01-25T06:51:16.866833Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
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
2023-01-25T06:51:16.866862Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:16.866878Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_callcode"::Berlin::0
2023-01-25T06:51:16.866887Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_callcode.json"
2023-01-25T06:51:16.866895Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:16.866902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:16.867071Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543776,
    events_root: None,
}
2023-01-25T06:51:16.867089Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
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
2023-01-25T06:51:16.867111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:16.867120Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_callcode"::London::0
2023-01-25T06:51:16.867127Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_callcode.json"
2023-01-25T06:51:16.867135Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:16.867141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:16.867269Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543776,
    events_root: None,
}
2023-01-25T06:51:16.867287Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
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
2023-01-25T06:51:16.867309Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:16.867318Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_callcode"::Merge::0
2023-01-25T06:51:16.867325Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_callcode.json"
2023-01-25T06:51:16.867334Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:16.867341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:16.867466Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543776,
    events_root: None,
}
2023-01-25T06:51:16.867484Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
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
2023-01-25T06:51:16.869574Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.92837ms
2023-01-25T06:51:17.127879Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_delegatecall.json", Total Files :: 1
2023-01-25T06:51:17.170066Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:17.170303Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:17.170308Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:17.170371Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:17.170373Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:17.170440Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:17.170443Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:17.170504Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:17.170587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:17.170590Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_delegatecall"::Istanbul::0
2023-01-25T06:51:17.170593Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_delegatecall.json"
2023-01-25T06:51:17.170596Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:17.170597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:17.542679Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2601600,
    events_root: None,
}
2023-01-25T06:51:17.542704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:17.542712Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_delegatecall"::Berlin::0
2023-01-25T06:51:17.542715Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_delegatecall.json"
2023-01-25T06:51:17.542720Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:17.542721Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:17.542924Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2601600,
    events_root: None,
}
2023-01-25T06:51:17.542934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:17.542937Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_delegatecall"::London::0
2023-01-25T06:51:17.542942Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_delegatecall.json"
2023-01-25T06:51:17.542946Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:17.542948Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:17.543130Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2601600,
    events_root: None,
}
2023-01-25T06:51:17.543140Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:17.543145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_delegatecall"::Merge::0
2023-01-25T06:51:17.543148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_delegatecall.json"
2023-01-25T06:51:17.543152Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:17.543154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:17.543343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2601600,
    events_root: None,
}
2023-01-25T06:51:17.544887Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:373.292377ms
2023-01-25T06:51:17.816299Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_staticcall.json", Total Files :: 1
2023-01-25T06:51:17.846424Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:17.846647Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:17.846666Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:17.846739Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:17.846742Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:17.846822Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:17.846826Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:17.846895Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:17.846968Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:17.846971Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_staticcall"::Istanbul::0
2023-01-25T06:51:17.846974Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_staticcall.json"
2023-01-25T06:51:17.846979Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:17.846980Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:18.231291Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1764913,
    events_root: None,
}
2023-01-25T06:51:18.231313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:18.231320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_staticcall"::Berlin::0
2023-01-25T06:51:18.231323Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_staticcall.json"
2023-01-25T06:51:18.231326Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:18.231327Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:18.231450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1764913,
    events_root: None,
}
2023-01-25T06:51:18.231458Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:18.231460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_staticcall"::London::0
2023-01-25T06:51:18.231462Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_staticcall.json"
2023-01-25T06:51:18.231465Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:18.231466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:18.231574Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1764913,
    events_root: None,
}
2023-01-25T06:51:18.231582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:18.231585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_failing_staticcall"::Merge::0
2023-01-25T06:51:18.231587Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_failing_staticcall.json"
2023-01-25T06:51:18.231590Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:18.231591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:18.231697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1764913,
    events_root: None,
}
2023-01-25T06:51:18.233137Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:385.287133ms
2023-01-25T06:51:18.499529Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_oog_after_deeper.json", Total Files :: 1
2023-01-25T06:51:18.533390Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:18.533585Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:18.533589Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:18.533642Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:18.533645Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:18.533705Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:18.533707Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:18.533765Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:18.533768Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-25T06:51:18.533818Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:18.533892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:18.533896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_oog_after_deeper"::Istanbul::0
2023-01-25T06:51:18.533899Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_oog_after_deeper.json"
2023-01-25T06:51:18.533903Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:18.533904Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:18.896307Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1816197,
    events_root: None,
}
2023-01-25T06:51:18.896329Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:18.896335Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_oog_after_deeper"::Berlin::0
2023-01-25T06:51:18.896338Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_oog_after_deeper.json"
2023-01-25T06:51:18.896342Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:18.896343Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:18.896466Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1816197,
    events_root: None,
}
2023-01-25T06:51:18.896473Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:18.896476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_oog_after_deeper"::London::0
2023-01-25T06:51:18.896479Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_oog_after_deeper.json"
2023-01-25T06:51:18.896482Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:18.896484Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:18.896593Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1816197,
    events_root: None,
}
2023-01-25T06:51:18.896603Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:18.896607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_oog_after_deeper"::Merge::0
2023-01-25T06:51:18.896610Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_oog_after_deeper.json"
2023-01-25T06:51:18.896613Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:18.896615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:18.896768Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1816197,
    events_root: None,
}
2023-01-25T06:51:18.898397Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.393395ms
2023-01-25T06:51:19.175305Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_callcode.json", Total Files :: 1
2023-01-25T06:51:19.204852Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:19.205045Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:19.205049Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:19.205101Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:19.205103Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:19.205162Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:19.205233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:19.205236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_callcode"::Istanbul::0
2023-01-25T06:51:19.205239Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_callcode.json"
2023-01-25T06:51:19.205243Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:19.205244Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:19.560633Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543706,
    events_root: None,
}
2023-01-25T06:51:19.560653Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=34): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:19.560668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:19.560676Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_callcode"::Berlin::0
2023-01-25T06:51:19.560678Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_callcode.json"
2023-01-25T06:51:19.560681Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:19.560683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:19.560802Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543706,
    events_root: None,
}
2023-01-25T06:51:19.560808Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=34): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:19.560818Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:19.560820Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_callcode"::London::0
2023-01-25T06:51:19.560822Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_callcode.json"
2023-01-25T06:51:19.560825Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:19.560826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:19.560923Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543706,
    events_root: None,
}
2023-01-25T06:51:19.560928Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=34): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:19.560938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:19.560940Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_callcode"::Merge::0
2023-01-25T06:51:19.560942Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_callcode.json"
2023-01-25T06:51:19.560945Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:19.560946Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:19.561032Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543706,
    events_root: None,
}
2023-01-25T06:51:19.561036Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=34): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:19.562865Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:356.198299ms
2023-01-25T06:51:19.840822Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_delegatecall.json", Total Files :: 1
2023-01-25T06:51:20.110552Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:20.110748Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:20.110752Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:20.110806Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:20.110808Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:20.110870Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:20.110942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:20.110945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_delegatecall"::Istanbul::0
2023-01-25T06:51:20.110949Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_delegatecall.json"
2023-01-25T06:51:20.110952Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:20.110955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:20.507124Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2651600,
    events_root: None,
}
2023-01-25T06:51:20.507147Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:20.507153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_delegatecall"::Berlin::0
2023-01-25T06:51:20.507155Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_delegatecall.json"
2023-01-25T06:51:20.507158Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:20.507160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:20.507361Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2651600,
    events_root: None,
}
2023-01-25T06:51:20.507370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:20.507373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_delegatecall"::London::0
2023-01-25T06:51:20.507376Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_delegatecall.json"
2023-01-25T06:51:20.507379Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:20.507380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:20.507552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2651600,
    events_root: None,
}
2023-01-25T06:51:20.507560Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:20.507563Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_delegatecall"::Merge::0
2023-01-25T06:51:20.507565Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_delegatecall.json"
2023-01-25T06:51:20.507569Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:20.507570Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:20.507740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2651600,
    events_root: None,
}
2023-01-25T06:51:20.509295Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:397.20178ms
2023-01-25T06:51:20.788037Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_staticcall.json", Total Files :: 1
2023-01-25T06:51:20.828585Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:20.828779Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:20.828782Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:20.828835Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:20.828837Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:20.828900Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:20.828970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:20.828973Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_staticcall"::Istanbul::0
2023-01-25T06:51:20.828976Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_staticcall.json"
2023-01-25T06:51:20.828980Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:20.828981Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:21.189565Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1764913,
    events_root: None,
}
2023-01-25T06:51:21.189589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:21.189595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_staticcall"::Berlin::0
2023-01-25T06:51:21.189598Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_staticcall.json"
2023-01-25T06:51:21.189601Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:21.189603Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:21.189725Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1764913,
    events_root: None,
}
2023-01-25T06:51:21.189733Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:21.189737Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_staticcall"::London::0
2023-01-25T06:51:21.189739Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_staticcall.json"
2023-01-25T06:51:21.189742Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:21.189743Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:21.189882Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1764913,
    events_root: None,
}
2023-01-25T06:51:21.189890Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:21.189892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_after_successful_staticcall"::Merge::0
2023-01-25T06:51:21.189894Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_after_successful_staticcall.json"
2023-01-25T06:51:21.189897Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:21.189899Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:21.190028Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1764913,
    events_root: None,
}
2023-01-25T06:51:21.191589Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.456452ms
2023-01-25T06:51:21.458931Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_bug.json", Total Files :: 1
2023-01-25T06:51:21.488722Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:21.488916Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:21.488921Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:21.488977Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:21.488979Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:21.489040Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:21.489112Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:21.489115Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_bug"::Istanbul::0
2023-01-25T06:51:21.489118Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_bug.json"
2023-01-25T06:51:21.489121Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:21.489123Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:21.851671Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711195,
    events_root: None,
}
2023-01-25T06:51:21.851694Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:21.851701Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_bug"::Berlin::0
2023-01-25T06:51:21.851704Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_bug.json"
2023-01-25T06:51:21.851708Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:21.851709Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:21.851834Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711195,
    events_root: None,
}
2023-01-25T06:51:21.851841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:21.851844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_bug"::London::0
2023-01-25T06:51:21.851846Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_bug.json"
2023-01-25T06:51:21.851849Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:21.851850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:21.851982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711195,
    events_root: None,
}
2023-01-25T06:51:21.851990Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:21.851994Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_bug"::Merge::0
2023-01-25T06:51:21.851996Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_bug.json"
2023-01-25T06:51:21.851998Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:21.852000Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:21.852107Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711195,
    events_root: None,
}
2023-01-25T06:51:21.853654Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.398617ms
2023-01-25T06:51:22.124393Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_following_successful_create.json", Total Files :: 1
2023-01-25T06:51:22.153675Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:22.153873Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:22.153877Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:22.153933Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:22.154004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:22.154007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_following_successful_create"::Istanbul::0
2023-01-25T06:51:22.154011Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_following_successful_create.json"
2023-01-25T06:51:22.154014Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:22.154016Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-25T06:51:22.791918Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13386185,
    events_root: None,
}
2023-01-25T06:51:22.791951Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:22.791958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_following_successful_create"::Berlin::0
2023-01-25T06:51:22.791962Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_following_successful_create.json"
2023-01-25T06:51:22.791966Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:22.791968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 204, 229, 246, 5, 48, 39, 94, 233, 49, 140, 225, 239, 249, 228, 191, 238, 129, 1, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-25T06:51:22.792582Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13587791,
    events_root: None,
}
2023-01-25T06:51:22.792603Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:22.792606Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_following_successful_create"::London::0
2023-01-25T06:51:22.792608Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_following_successful_create.json"
2023-01-25T06:51:22.792611Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:22.792612Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 206, 105, 18, 180, 86, 169, 134, 66, 145, 242, 213, 71, 127, 184, 201, 186, 98, 26, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-25T06:51:22.793159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13415689,
    events_root: None,
}
2023-01-25T06:51:22.793177Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:22.793180Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_following_successful_create"::Merge::0
2023-01-25T06:51:22.793182Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_following_successful_create.json"
2023-01-25T06:51:22.793186Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:22.793188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 146, 186, 46, 153, 226, 84, 67, 25, 239, 102, 183, 123, 143, 110, 42, 204, 247, 6, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-25T06:51:22.793734Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13552942,
    events_root: None,
}
2023-01-25T06:51:22.795334Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:640.083639ms
2023-01-25T06:51:23.074316Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial.json", Total Files :: 1
2023-01-25T06:51:23.103923Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:23.104127Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:23.104131Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:23.104187Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:23.104261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:23.104264Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial"::Istanbul::0
2023-01-25T06:51:23.104267Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial.json"
2023-01-25T06:51:23.104270Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:23.104272Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:23.496846Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526849,
    events_root: None,
}
2023-01-25T06:51:23.496869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:23.496877Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial"::Berlin::0
2023-01-25T06:51:23.496880Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial.json"
2023-01-25T06:51:23.496883Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:23.496884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:23.497002Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526849,
    events_root: None,
}
2023-01-25T06:51:23.497010Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:23.497013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial"::London::0
2023-01-25T06:51:23.497015Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial.json"
2023-01-25T06:51:23.497017Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:23.497019Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:23.497104Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526849,
    events_root: None,
}
2023-01-25T06:51:23.497110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:23.497112Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial"::Merge::0
2023-01-25T06:51:23.497114Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial.json"
2023-01-25T06:51:23.497116Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:23.497118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:23.497201Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526849,
    events_root: None,
}
2023-01-25T06:51:23.498631Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:393.289062ms
2023-01-25T06:51:23.757863Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial_zero_read.json", Total Files :: 1
2023-01-25T06:51:23.787877Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:23.788080Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:23.788085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:23.788141Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:23.788216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:23.788219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial_zero_read"::Istanbul::0
2023-01-25T06:51:23.788222Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial_zero_read.json"
2023-01-25T06:51:23.788225Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:23.788227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.171322Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1533865,
    events_root: None,
}
2023-01-25T06:51:24.171347Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-25T06:51:24.171357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial_zero_read"::Istanbul::1
2023-01-25T06:51:24.171360Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial_zero_read.json"
2023-01-25T06:51:24.171364Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T06:51:24.171366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.171491Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1537577,
    events_root: None,
}
2023-01-25T06:51:24.171499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:24.171503Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial_zero_read"::Berlin::0
2023-01-25T06:51:24.171505Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial_zero_read.json"
2023-01-25T06:51:24.171510Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:24.171512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.171606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1533865,
    events_root: None,
}
2023-01-25T06:51:24.171615Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-25T06:51:24.171618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial_zero_read"::Berlin::1
2023-01-25T06:51:24.171622Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial_zero_read.json"
2023-01-25T06:51:24.171626Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T06:51:24.171628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.171718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1537577,
    events_root: None,
}
2023-01-25T06:51:24.171725Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:24.171728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial_zero_read"::London::0
2023-01-25T06:51:24.171731Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial_zero_read.json"
2023-01-25T06:51:24.171735Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:24.171737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.171829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1533865,
    events_root: None,
}
2023-01-25T06:51:24.171839Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T06:51:24.171842Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial_zero_read"::London::1
2023-01-25T06:51:24.171844Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial_zero_read.json"
2023-01-25T06:51:24.171846Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T06:51:24.171848Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.171954Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1537577,
    events_root: None,
}
2023-01-25T06:51:24.171961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:24.171964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial_zero_read"::Merge::0
2023-01-25T06:51:24.171966Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial_zero_read.json"
2023-01-25T06:51:24.171969Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:24.171970Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.172050Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1533865,
    events_root: None,
}
2023-01-25T06:51:24.172057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T06:51:24.172059Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatasize_initial_zero_read"::Merge::1
2023-01-25T06:51:24.172062Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/returndatasize_initial_zero_read.json"
2023-01-25T06:51:24.172064Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T06:51:24.172066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.172145Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1537577,
    events_root: None,
}
2023-01-25T06:51:24.173560Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:384.279381ms
2023-01-25T06:51:24.455696Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json", Total Files :: 1
2023-01-25T06:51:24.518440Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:24.518632Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:24.518635Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:24.518692Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:24.518694Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:24.518755Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:24.518757Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:24.518802Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:24.518804Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-25T06:51:24.518857Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:24.518858Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-25T06:51:24.518923Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:24.518926Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-25T06:51:24.518986Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:24.519057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:24.519060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::0
2023-01-25T06:51:24.519063Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:24.519067Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:24.519068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.905351Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5994173,
    events_root: None,
}
2023-01-25T06:51:24.905374Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-25T06:51:24.905380Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::1
2023-01-25T06:51:24.905383Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:24.905386Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:24.905387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.905543Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1763042,
    events_root: None,
}
2023-01-25T06:51:24.905550Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=452): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:24.905565Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-25T06:51:24.905569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::2
2023-01-25T06:51:24.905571Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:24.905575Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:24.905577Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.905981Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5896853,
    events_root: None,
}
2023-01-25T06:51:24.905992Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-25T06:51:24.905995Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::3
2023-01-25T06:51:24.905997Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:24.906000Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:24.906001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:24.906238Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4013155,
    events_root: None,
}
2023-01-25T06:51:24.906247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-25T06:51:24.906249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::4
2023-01-25T06:51:24.906251Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:24.906254Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:24.906255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [138, 246, 167, 175, 48, 216, 64, 186, 19, 126, 143, 63, 52, 213, 76, 251, 139, 235, 166, 226, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
2023-01-25T06:51:25.173459Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17613952,
    events_root: None,
}
2023-01-25T06:51:25.173497Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-25T06:51:25.173503Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::5
2023-01-25T06:51:25.173506Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.173509Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.173510Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [225, 155, 21, 208, 28, 88, 131, 250, 111, 198, 15, 186, 205, 28, 53, 181, 213, 222, 195, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
2023-01-25T06:51:25.174336Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15835472,
    events_root: None,
}
2023-01-25T06:51:25.174357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-25T06:51:25.174361Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::6
2023-01-25T06:51:25.174363Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.174366Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.174367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.174755Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7066337,
    events_root: None,
}
2023-01-25T06:51:25.174768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-25T06:51:25.174770Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::7
2023-01-25T06:51:25.174772Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.174775Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.174776Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.175001Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3665249,
    events_root: None,
}
2023-01-25T06:51:25.175007Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.175020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-25T06:51:25.175023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::8
2023-01-25T06:51:25.175025Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.175028Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.175031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.175497Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6311643,
    events_root: None,
}
2023-01-25T06:51:25.175509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-25T06:51:25.175512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::9
2023-01-25T06:51:25.175514Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.175517Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.175518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.175847Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5376667,
    events_root: None,
}
2023-01-25T06:51:25.175858Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-25T06:51:25.175861Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::10
2023-01-25T06:51:25.175864Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.175866Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.175868Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [123, 63, 14, 251, 163, 176, 12, 252, 69, 58, 218, 72, 80, 74, 99, 63, 234, 44, 140, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
2023-01-25T06:51:25.176578Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17822259,
    events_root: None,
}
2023-01-25T06:51:25.176599Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-25T06:51:25.176602Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::11
2023-01-25T06:51:25.176604Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.176607Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.176608Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [32, 239, 250, 174, 181, 181, 88, 124, 201, 135, 137, 70, 147, 254, 247, 160, 218, 179, 227, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([90, 217, 32, 146, 24, 201, 117, 10, 10, 210, 28, 70, 31, 30, 132, 56, 243, 180, 75, 35]) }
2023-01-25T06:51:25.177306Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16680723,
    events_root: None,
}
2023-01-25T06:51:25.177327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-25T06:51:25.177330Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::12
2023-01-25T06:51:25.177332Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.177335Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.177336Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.177699Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7077851,
    events_root: None,
}
2023-01-25T06:51:25.177712Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-25T06:51:25.177714Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::13
2023-01-25T06:51:25.177717Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.177719Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.177721Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.177945Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3671585,
    events_root: None,
}
2023-01-25T06:51:25.177951Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.177963Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-25T06:51:25.177965Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::14
2023-01-25T06:51:25.177967Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.177969Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.177971Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.178420Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6326533,
    events_root: None,
}
2023-01-25T06:51:25.178434Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-25T06:51:25.178437Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::15
2023-01-25T06:51:25.178440Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.178443Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.178445Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.178785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5388181,
    events_root: None,
}
2023-01-25T06:51:25.178800Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 16
2023-01-25T06:51:25.178803Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::16
2023-01-25T06:51:25.178806Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.178810Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.178811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [122, 165, 160, 111, 221, 77, 189, 189, 125, 83, 232, 170, 218, 236, 99, 116, 73, 98, 162, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 33, 161, 133, 93, 209, 38, 110, 16, 16, 237, 126, 30, 78, 59, 192, 15, 148, 83, 57]) }
2023-01-25T06:51:25.179531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17698587,
    events_root: None,
}
2023-01-25T06:51:25.179552Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 17
2023-01-25T06:51:25.179555Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::17
2023-01-25T06:51:25.179557Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.179560Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.179562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [168, 191, 172, 166, 110, 67, 1, 187, 50, 249, 87, 119, 137, 251, 78, 5, 233, 230, 90, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([115, 209, 18, 63, 181, 115, 165, 219, 137, 112, 100, 108, 193, 38, 167, 163, 136, 114, 38, 238]) }
2023-01-25T06:51:25.180289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16148504,
    events_root: None,
}
2023-01-25T06:51:25.180311Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 18
2023-01-25T06:51:25.180314Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::18
2023-01-25T06:51:25.180316Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.180320Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.180321Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.180757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7085056,
    events_root: None,
}
2023-01-25T06:51:25.180769Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 19
2023-01-25T06:51:25.180772Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::19
2023-01-25T06:51:25.180774Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.180777Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.180779Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.181028Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3677921,
    events_root: None,
}
2023-01-25T06:51:25.181034Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.181047Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 20
2023-01-25T06:51:25.181052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::20
2023-01-25T06:51:25.181055Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.181058Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.181060Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.181495Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6333738,
    events_root: None,
}
2023-01-25T06:51:25.181507Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 21
2023-01-25T06:51:25.181510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::21
2023-01-25T06:51:25.181513Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.181516Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.181518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.181917Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5395386,
    events_root: None,
}
2023-01-25T06:51:25.181928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 22
2023-01-25T06:51:25.181930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::22
2023-01-25T06:51:25.181933Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.181935Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.181937Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [112, 68, 19, 37, 117, 76, 12, 39, 178, 17, 165, 60, 4, 198, 194, 134, 160, 185, 28, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 101, 220, 118, 126, 227, 221, 111, 130, 239, 232, 201, 210, 70, 69, 50, 207, 38, 17, 72]) }
2023-01-25T06:51:25.182720Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17910746,
    events_root: None,
}
2023-01-25T06:51:25.182743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 23
2023-01-25T06:51:25.182745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::23
2023-01-25T06:51:25.182748Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.182750Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.182752Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [128, 247, 134, 212, 123, 123, 53, 168, 66, 194, 135, 141, 236, 252, 0, 171, 41, 32, 127, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 34, 247, 70, 142, 122, 19, 174, 255, 98, 183, 37, 253, 210, 62, 191, 224, 79, 199, 228]) }
2023-01-25T06:51:25.183458Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16208565,
    events_root: None,
}
2023-01-25T06:51:25.183480Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 24
2023-01-25T06:51:25.183483Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::24
2023-01-25T06:51:25.183485Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.183488Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.183489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.183859Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7066337,
    events_root: None,
}
2023-01-25T06:51:25.183871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 25
2023-01-25T06:51:25.183874Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::25
2023-01-25T06:51:25.183876Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.183879Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.183880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.184114Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3665249,
    events_root: None,
}
2023-01-25T06:51:25.184120Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.184132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 26
2023-01-25T06:51:25.184135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::26
2023-01-25T06:51:25.184138Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.184141Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.184142Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.184552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6311643,
    events_root: None,
}
2023-01-25T06:51:25.184564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 27
2023-01-25T06:51:25.184567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::27
2023-01-25T06:51:25.184570Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.184572Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.184574Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.184964Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5376667,
    events_root: None,
}
2023-01-25T06:51:25.184975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 28
2023-01-25T06:51:25.184978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::28
2023-01-25T06:51:25.184980Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.184983Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.184984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [234, 161, 245, 17, 112, 6, 75, 117, 59, 56, 63, 87, 83, 228, 94, 157, 64, 12, 161, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([221, 202, 25, 212, 34, 2, 50, 123, 41, 75, 186, 155, 123, 166, 127, 9, 228, 237, 116, 209]) }
2023-01-25T06:51:25.185704Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17804110,
    events_root: None,
}
2023-01-25T06:51:25.185726Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 29
2023-01-25T06:51:25.185729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::29
2023-01-25T06:51:25.185731Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.185734Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.185736Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.186166Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6465466,
    events_root: None,
}
2023-01-25T06:51:25.186179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 30
2023-01-25T06:51:25.186182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::30
2023-01-25T06:51:25.186184Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.186186Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.186188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.186494Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5635361,
    events_root: None,
}
2023-01-25T06:51:25.186505Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 31
2023-01-25T06:51:25.186508Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::31
2023-01-25T06:51:25.186510Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.186513Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.186514Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.186754Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3711831,
    events_root: None,
}
2023-01-25T06:51:25.186760Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.186772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 32
2023-01-25T06:51:25.186775Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::32
2023-01-25T06:51:25.186778Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.186781Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.186782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.187050Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3949507,
    events_root: None,
}
2023-01-25T06:51:25.187060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 33
2023-01-25T06:51:25.187063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::33
2023-01-25T06:51:25.187065Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.187069Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.187070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.187333Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3945691,
    events_root: None,
}
2023-01-25T06:51:25.187343Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 34
2023-01-25T06:51:25.187346Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::34
2023-01-25T06:51:25.187348Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.187351Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.187352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [178, 118, 217, 229, 17, 27, 93, 93, 16, 171, 155, 225, 41, 115, 220, 234, 51, 24, 245, 143, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([74, 138, 107, 177, 65, 173, 106, 127, 111, 235, 64, 25, 56, 77, 152, 139, 121, 241, 216, 113]) }
2023-01-25T06:51:25.188190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17705735,
    events_root: None,
}
2023-01-25T06:51:25.188213Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 35
2023-01-25T06:51:25.188216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Istanbul::35
2023-01-25T06:51:25.188218Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.188221Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.188222Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [45, 189, 121, 18, 63, 166, 102, 132, 250, 121, 216, 182, 75, 53, 212, 94, 230, 223, 11, 251, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([126, 248, 213, 18, 73, 109, 79, 84, 218, 211, 209, 213, 172, 193, 146, 154, 144, 35, 152, 99]) }
2023-01-25T06:51:25.188925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15012501,
    events_root: None,
}
2023-01-25T06:51:25.188947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:25.188950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::0
2023-01-25T06:51:25.188952Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.188954Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.188956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.189243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5724482,
    events_root: None,
}
2023-01-25T06:51:25.189254Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-25T06:51:25.189257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::1
2023-01-25T06:51:25.189259Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.189261Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.189263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.189381Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1763042,
    events_root: None,
}
2023-01-25T06:51:25.189387Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=452): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.189399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-25T06:51:25.189402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::2
2023-01-25T06:51:25.189404Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.189406Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.189408Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.189804Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5896853,
    events_root: None,
}
2023-01-25T06:51:25.189817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-25T06:51:25.189819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::3
2023-01-25T06:51:25.189822Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.189824Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.189826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.190078Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4013155,
    events_root: None,
}
2023-01-25T06:51:25.190089Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-25T06:51:25.190092Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::4
2023-01-25T06:51:25.190094Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.190096Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.190098Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [241, 131, 118, 85, 134, 72, 114, 66, 162, 103, 94, 184, 112, 7, 234, 42, 27, 108, 112, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 103, 245, 189, 168, 73, 149, 238, 158, 100, 244, 162, 2, 157, 240, 169, 24, 108, 156, 146]) }
2023-01-25T06:51:25.190819Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17798710,
    events_root: None,
}
2023-01-25T06:51:25.190840Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-25T06:51:25.190843Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::5
2023-01-25T06:51:25.190846Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.190849Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.190851Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.191321Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6475830,
    events_root: None,
}
2023-01-25T06:51:25.191334Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-25T06:51:25.191337Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::6
2023-01-25T06:51:25.191339Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.191342Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.191344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.191711Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7066337,
    events_root: None,
}
2023-01-25T06:51:25.191722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-25T06:51:25.191725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::7
2023-01-25T06:51:25.191727Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.191730Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.191733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.191961Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3665249,
    events_root: None,
}
2023-01-25T06:51:25.191967Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.191980Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-25T06:51:25.191982Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::8
2023-01-25T06:51:25.191984Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.191987Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.191988Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.192390Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6311643,
    events_root: None,
}
2023-01-25T06:51:25.192403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-25T06:51:25.192407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::9
2023-01-25T06:51:25.192409Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.192411Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.192413Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.192748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5376667,
    events_root: None,
}
2023-01-25T06:51:25.192759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-25T06:51:25.192762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::10
2023-01-25T06:51:25.192764Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.192767Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.192768Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [72, 157, 77, 48, 213, 7, 63, 24, 41, 120, 253, 81, 121, 196, 35, 249, 131, 239, 155, 249, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([59, 53, 249, 29, 97, 100, 74, 37, 144, 142, 18, 90, 172, 2, 157, 156, 29, 149, 16, 132]) }
2023-01-25T06:51:25.193476Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18016967,
    events_root: None,
}
2023-01-25T06:51:25.193501Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-25T06:51:25.193506Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::11
2023-01-25T06:51:25.193508Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.193511Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.193514Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.193931Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6465466,
    events_root: None,
}
2023-01-25T06:51:25.193943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-25T06:51:25.193946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::12
2023-01-25T06:51:25.193948Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.193951Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.193952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.194372Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7077851,
    events_root: None,
}
2023-01-25T06:51:25.194383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-25T06:51:25.194386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::13
2023-01-25T06:51:25.194389Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.194392Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.194393Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.194621Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3671585,
    events_root: None,
}
2023-01-25T06:51:25.194626Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.194639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-25T06:51:25.194641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::14
2023-01-25T06:51:25.194643Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.194646Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.194647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.195048Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6326533,
    events_root: None,
}
2023-01-25T06:51:25.195060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-25T06:51:25.195063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::15
2023-01-25T06:51:25.195066Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.195069Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.195070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.195402Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5388181,
    events_root: None,
}
2023-01-25T06:51:25.195413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-25T06:51:25.195416Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::16
2023-01-25T06:51:25.195418Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.195420Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.195422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 203, 36, 67, 25, 224, 165, 39, 239, 165, 9, 174, 132, 88, 33, 218, 22, 163, 184, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([42, 8, 0, 137, 245, 202, 239, 57, 123, 81, 148, 98, 201, 144, 167, 86, 38, 89, 1, 145]) }
2023-01-25T06:51:25.196150Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18191127,
    events_root: None,
}
2023-01-25T06:51:25.196172Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-25T06:51:25.196175Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::17
2023-01-25T06:51:25.196177Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.196180Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.196181Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.196601Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6471802,
    events_root: None,
}
2023-01-25T06:51:25.196616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-25T06:51:25.196618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::18
2023-01-25T06:51:25.196620Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.196624Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.196625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.197013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7085056,
    events_root: None,
}
2023-01-25T06:51:25.197025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-25T06:51:25.197028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::19
2023-01-25T06:51:25.197030Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.197032Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.197034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.197312Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3677921,
    events_root: None,
}
2023-01-25T06:51:25.197318Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.197331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 20
2023-01-25T06:51:25.197333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::20
2023-01-25T06:51:25.197335Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.197337Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.197339Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.197744Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6333738,
    events_root: None,
}
2023-01-25T06:51:25.197756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 21
2023-01-25T06:51:25.197759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::21
2023-01-25T06:51:25.197761Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.197763Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.197766Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.198099Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5395386,
    events_root: None,
}
2023-01-25T06:51:25.198110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 22
2023-01-25T06:51:25.198113Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::22
2023-01-25T06:51:25.198116Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.198119Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.198120Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [94, 49, 119, 38, 174, 59, 145, 111, 98, 29, 213, 238, 78, 195, 65, 215, 154, 81, 212, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([245, 247, 167, 109, 171, 19, 147, 219, 109, 152, 254, 206, 145, 95, 196, 82, 59, 231, 146, 108]) }
2023-01-25T06:51:25.198846Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17989618,
    events_root: None,
}
2023-01-25T06:51:25.198868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 23
2023-01-25T06:51:25.198870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::23
2023-01-25T06:51:25.198874Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.198876Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.198878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.199331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6478138,
    events_root: None,
}
2023-01-25T06:51:25.199344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 24
2023-01-25T06:51:25.199347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::24
2023-01-25T06:51:25.199349Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.199352Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.199353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.199769Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7066337,
    events_root: None,
}
2023-01-25T06:51:25.199781Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 25
2023-01-25T06:51:25.199784Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::25
2023-01-25T06:51:25.199786Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.199790Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.199791Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.200058Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3665249,
    events_root: None,
}
2023-01-25T06:51:25.200064Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.200076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 26
2023-01-25T06:51:25.200079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::26
2023-01-25T06:51:25.200081Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.200084Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.200086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.200551Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6311643,
    events_root: None,
}
2023-01-25T06:51:25.200564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 27
2023-01-25T06:51:25.200567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::27
2023-01-25T06:51:25.200569Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.200571Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.200573Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.200906Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5376667,
    events_root: None,
}
2023-01-25T06:51:25.200918Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 28
2023-01-25T06:51:25.200920Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::28
2023-01-25T06:51:25.200924Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.200926Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.200928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [35, 179, 240, 213, 51, 252, 217, 97, 81, 169, 141, 35, 255, 59, 191, 4, 113, 20, 178, 124, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([172, 213, 217, 59, 199, 164, 245, 110, 126, 219, 117, 176, 255, 50, 179, 203, 237, 224, 86, 53]) }
2023-01-25T06:51:25.201701Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17669672,
    events_root: None,
}
2023-01-25T06:51:25.201723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 29
2023-01-25T06:51:25.201726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::29
2023-01-25T06:51:25.201728Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.201731Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.201732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.202156Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6465466,
    events_root: None,
}
2023-01-25T06:51:25.202168Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 30
2023-01-25T06:51:25.202172Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::30
2023-01-25T06:51:25.202174Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.202177Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.202178Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.202474Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5635361,
    events_root: None,
}
2023-01-25T06:51:25.202485Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 31
2023-01-25T06:51:25.202488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::31
2023-01-25T06:51:25.202490Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.202493Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.202494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.202730Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3711831,
    events_root: None,
}
2023-01-25T06:51:25.202736Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.202747Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 32
2023-01-25T06:51:25.202750Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::32
2023-01-25T06:51:25.202752Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.202755Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.202757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.203020Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3949507,
    events_root: None,
}
2023-01-25T06:51:25.203031Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 33
2023-01-25T06:51:25.203033Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::33
2023-01-25T06:51:25.203035Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.203038Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.203039Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.203355Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3945691,
    events_root: None,
}
2023-01-25T06:51:25.203366Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 34
2023-01-25T06:51:25.203369Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::34
2023-01-25T06:51:25.203371Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.203373Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.203375Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [56, 78, 40, 124, 118, 80, 110, 234, 255, 90, 220, 147, 46, 20, 81, 17, 178, 80, 88, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([138, 38, 243, 153, 218, 225, 55, 155, 27, 229, 106, 36, 160, 218, 25, 26, 79, 118, 84, 124]) }
2023-01-25T06:51:25.204105Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17930177,
    events_root: None,
}
2023-01-25T06:51:25.204128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 35
2023-01-25T06:51:25.204131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Berlin::35
2023-01-25T06:51:25.204134Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.204136Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.204138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.204577Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6513398,
    events_root: None,
}
2023-01-25T06:51:25.204591Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:25.204594Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::0
2023-01-25T06:51:25.204596Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.204598Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.204599Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.204884Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5725931,
    events_root: None,
}
2023-01-25T06:51:25.204895Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T06:51:25.204898Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::1
2023-01-25T06:51:25.204900Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.204903Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.204904Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.205019Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1763141,
    events_root: None,
}
2023-01-25T06:51:25.205023Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=452): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.205033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-25T06:51:25.205035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::2
2023-01-25T06:51:25.205037Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.205040Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.205042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.205433Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5897050,
    events_root: None,
}
2023-01-25T06:51:25.205445Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-25T06:51:25.205448Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::3
2023-01-25T06:51:25.205450Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.205453Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.205454Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.205715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4013254,
    events_root: None,
}
2023-01-25T06:51:25.205725Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-25T06:51:25.205728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::4
2023-01-25T06:51:25.205731Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.205733Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.205734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [163, 135, 255, 118, 66, 156, 151, 100, 126, 67, 154, 1, 227, 215, 98, 79, 249, 235, 122, 231, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 79, 125, 93, 55, 208, 234, 109, 248, 252, 50, 181, 233, 25, 133, 95, 16, 4, 250, 212]) }
2023-01-25T06:51:25.206489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17627056,
    events_root: None,
}
2023-01-25T06:51:25.206511Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-25T06:51:25.206514Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::5
2023-01-25T06:51:25.206516Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.206519Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.206520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.206937Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6477278,
    events_root: None,
}
2023-01-25T06:51:25.206949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-25T06:51:25.206952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::6
2023-01-25T06:51:25.206954Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.206956Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.206958Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.207325Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7067785,
    events_root: None,
}
2023-01-25T06:51:25.207338Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-25T06:51:25.207340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::7
2023-01-25T06:51:25.207343Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.207345Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.207347Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.207573Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3665348,
    events_root: None,
}
2023-01-25T06:51:25.207579Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.207590Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-25T06:51:25.207593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::8
2023-01-25T06:51:25.207595Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.207598Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.207599Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.208009Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6311840,
    events_root: None,
}
2023-01-25T06:51:25.208021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-25T06:51:25.208024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::9
2023-01-25T06:51:25.208026Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.208030Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.208031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.208366Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5376765,
    events_root: None,
}
2023-01-25T06:51:25.208378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-25T06:51:25.208380Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::10
2023-01-25T06:51:25.208383Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.208385Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.208387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [145, 164, 96, 175, 195, 253, 103, 149, 13, 63, 252, 225, 50, 125, 28, 27, 95, 218, 69, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 95, 145, 17, 53, 205, 188, 252, 222, 81, 19, 14, 225, 44, 173, 102, 10, 139, 61, 204]) }
2023-01-25T06:51:25.209132Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18243527,
    events_root: None,
}
2023-01-25T06:51:25.209153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-25T06:51:25.209157Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::11
2023-01-25T06:51:25.209159Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.209162Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.209164Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.209637Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6466915,
    events_root: None,
}
2023-01-25T06:51:25.209650Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-25T06:51:25.209653Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::12
2023-01-25T06:51:25.209655Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.209658Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.209659Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.210026Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7079300,
    events_root: None,
}
2023-01-25T06:51:25.210038Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-25T06:51:25.210040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::13
2023-01-25T06:51:25.210044Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.210046Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.210048Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.210271Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3671684,
    events_root: None,
}
2023-01-25T06:51:25.210277Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.210289Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-25T06:51:25.210292Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::14
2023-01-25T06:51:25.210294Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.210296Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.210298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.210702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6326730,
    events_root: None,
}
2023-01-25T06:51:25.210715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-25T06:51:25.210718Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::15
2023-01-25T06:51:25.210720Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.210723Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.210724Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.211052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5388279,
    events_root: None,
}
2023-01-25T06:51:25.211064Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-25T06:51:25.211066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::16
2023-01-25T06:51:25.211069Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.211072Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.211073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [44, 17, 3, 99, 191, 93, 52, 231, 144, 185, 46, 66, 249, 56, 60, 28, 137, 213, 132, 212, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([36, 157, 234, 94, 37, 166, 2, 133, 61, 174, 211, 48, 33, 142, 84, 86, 31, 155, 191, 251]) }
2023-01-25T06:51:25.211768Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17753534,
    events_root: None,
}
2023-01-25T06:51:25.211790Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-25T06:51:25.211792Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::17
2023-01-25T06:51:25.211794Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.211797Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.211798Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.212223Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6473251,
    events_root: None,
}
2023-01-25T06:51:25.212236Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-25T06:51:25.212239Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::18
2023-01-25T06:51:25.212242Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.212245Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.212246Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.212666Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7086505,
    events_root: None,
}
2023-01-25T06:51:25.212678Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-25T06:51:25.212681Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::19
2023-01-25T06:51:25.212683Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.212685Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.212688Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.212910Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3678020,
    events_root: None,
}
2023-01-25T06:51:25.212916Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.212927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-25T06:51:25.212930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::20
2023-01-25T06:51:25.212932Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.212934Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.212935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.213361Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6333935,
    events_root: None,
}
2023-01-25T06:51:25.213374Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-25T06:51:25.213377Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::21
2023-01-25T06:51:25.213380Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.213382Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.213385Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.213722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5395484,
    events_root: None,
}
2023-01-25T06:51:25.213733Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-25T06:51:25.213736Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::22
2023-01-25T06:51:25.213738Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.213741Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.213743Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [45, 57, 187, 8, 34, 109, 230, 150, 246, 189, 22, 114, 93, 73, 193, 151, 185, 96, 244, 134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 221, 7, 113, 89, 247, 138, 119, 225, 55, 135, 221, 132, 165, 82, 22, 202, 208, 233, 91]) }
2023-01-25T06:51:25.214453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17991002,
    events_root: None,
}
2023-01-25T06:51:25.214475Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-25T06:51:25.214478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::23
2023-01-25T06:51:25.214481Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.214483Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.214485Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.214974Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6479587,
    events_root: None,
}
2023-01-25T06:51:25.214988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 24
2023-01-25T06:51:25.214990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::24
2023-01-25T06:51:25.214993Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.214998Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.215000Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.215489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7067785,
    events_root: None,
}
2023-01-25T06:51:25.215502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 25
2023-01-25T06:51:25.215504Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::25
2023-01-25T06:51:25.215506Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.215509Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.215511Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.215796Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3665348,
    events_root: None,
}
2023-01-25T06:51:25.215801Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.215813Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 26
2023-01-25T06:51:25.215817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::26
2023-01-25T06:51:25.215819Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.215821Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.215823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.216255Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6311840,
    events_root: None,
}
2023-01-25T06:51:25.216268Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 27
2023-01-25T06:51:25.216271Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::27
2023-01-25T06:51:25.216273Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.216276Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.216278Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.216610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5376765,
    events_root: None,
}
2023-01-25T06:51:25.216621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 28
2023-01-25T06:51:25.216623Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::28
2023-01-25T06:51:25.216626Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.216628Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.216630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [240, 177, 113, 125, 133, 95, 107, 195, 121, 146, 240, 197, 90, 207, 141, 30, 210, 151, 69, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([29, 140, 230, 138, 107, 84, 150, 22, 173, 23, 154, 28, 236, 246, 46, 198, 72, 180, 189, 9]) }
2023-01-25T06:51:25.217395Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17962291,
    events_root: None,
}
2023-01-25T06:51:25.217417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 29
2023-01-25T06:51:25.217420Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::29
2023-01-25T06:51:25.217422Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.217425Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.217426Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.217851Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6466915,
    events_root: None,
}
2023-01-25T06:51:25.217864Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 30
2023-01-25T06:51:25.217867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::30
2023-01-25T06:51:25.217869Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.217872Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.217873Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.218169Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5636810,
    events_root: None,
}
2023-01-25T06:51:25.218182Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 31
2023-01-25T06:51:25.218184Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::31
2023-01-25T06:51:25.218186Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.218189Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.218190Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.218424Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3711930,
    events_root: None,
}
2023-01-25T06:51:25.218429Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.218441Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 32
2023-01-25T06:51:25.218444Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::32
2023-01-25T06:51:25.218446Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.218448Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.218451Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.218768Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3949605,
    events_root: None,
}
2023-01-25T06:51:25.218780Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 33
2023-01-25T06:51:25.218783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::33
2023-01-25T06:51:25.218785Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.218788Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.218789Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.219050Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3945790,
    events_root: None,
}
2023-01-25T06:51:25.219061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 34
2023-01-25T06:51:25.219064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::34
2023-01-25T06:51:25.219066Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.219068Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.219070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [79, 57, 117, 186, 225, 31, 71, 10, 71, 123, 136, 128, 89, 9, 200, 64, 74, 151, 13, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([26, 240, 28, 195, 132, 99, 78, 96, 33, 68, 142, 205, 74, 246, 255, 91, 152, 252, 192, 155]) }
2023-01-25T06:51:25.219781Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17786891,
    events_root: None,
}
2023-01-25T06:51:25.219803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 35
2023-01-25T06:51:25.219805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::London::35
2023-01-25T06:51:25.219809Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.219811Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.219813Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.220252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6513497,
    events_root: None,
}
2023-01-25T06:51:25.220265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:25.220268Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::0
2023-01-25T06:51:25.220270Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.220273Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.220275Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.220563Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5725931,
    events_root: None,
}
2023-01-25T06:51:25.220574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T06:51:25.220577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::1
2023-01-25T06:51:25.220579Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.220582Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.220583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.220702Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1763141,
    events_root: None,
}
2023-01-25T06:51:25.220708Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=452): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.220719Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-25T06:51:25.220722Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::2
2023-01-25T06:51:25.220725Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.220729Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.220731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.221140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5897050,
    events_root: None,
}
2023-01-25T06:51:25.221153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-25T06:51:25.221155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::3
2023-01-25T06:51:25.221158Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.221160Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.221161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.221468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4013254,
    events_root: None,
}
2023-01-25T06:51:25.221478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-25T06:51:25.221481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::4
2023-01-25T06:51:25.221483Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.221485Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.221487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [149, 135, 152, 219, 39, 115, 41, 85, 239, 255, 176, 175, 201, 245, 10, 27, 176, 19, 113, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([238, 67, 40, 127, 153, 170, 231, 31, 27, 189, 74, 95, 145, 13, 91, 152, 106, 149, 37, 30]) }
2023-01-25T06:51:25.222224Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18078161,
    events_root: None,
}
2023-01-25T06:51:25.222245Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-25T06:51:25.222248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::5
2023-01-25T06:51:25.222251Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.222254Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.222255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.222680Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6477278,
    events_root: None,
}
2023-01-25T06:51:25.222693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-25T06:51:25.222696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::6
2023-01-25T06:51:25.222698Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.222700Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.222702Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.223066Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7067785,
    events_root: None,
}
2023-01-25T06:51:25.223078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-25T06:51:25.223082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::7
2023-01-25T06:51:25.223083Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.223086Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.223087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.223311Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3665348,
    events_root: None,
}
2023-01-25T06:51:25.223317Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.223330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-25T06:51:25.223333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::8
2023-01-25T06:51:25.223334Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.223337Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.223338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.223739Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6311840,
    events_root: None,
}
2023-01-25T06:51:25.223751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-25T06:51:25.223754Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::9
2023-01-25T06:51:25.223756Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.223759Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.223760Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.224099Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5376765,
    events_root: None,
}
2023-01-25T06:51:25.224112Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-25T06:51:25.224115Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::10
2023-01-25T06:51:25.224117Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.224120Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.224122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [105, 84, 46, 58, 129, 168, 208, 17, 134, 176, 52, 53, 12, 237, 133, 115, 170, 29, 22, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([2, 180, 255, 222, 75, 104, 55, 64, 26, 55, 66, 244, 63, 138, 191, 90, 119, 72, 198, 78]) }
2023-01-25T06:51:25.224911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17919841,
    events_root: None,
}
2023-01-25T06:51:25.224932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-25T06:51:25.224936Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::11
2023-01-25T06:51:25.224938Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.224941Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.224942Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.225360Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6466915,
    events_root: None,
}
2023-01-25T06:51:25.225373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-25T06:51:25.225376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::12
2023-01-25T06:51:25.225378Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.225381Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.225382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.225752Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7079300,
    events_root: None,
}
2023-01-25T06:51:25.225764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-25T06:51:25.225767Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::13
2023-01-25T06:51:25.225769Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.225772Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.225773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.225996Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3671684,
    events_root: None,
}
2023-01-25T06:51:25.226002Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.226014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-25T06:51:25.226017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::14
2023-01-25T06:51:25.226019Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.226021Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.226023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.226424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6326730,
    events_root: None,
}
2023-01-25T06:51:25.226437Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-25T06:51:25.226440Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::15
2023-01-25T06:51:25.226442Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.226444Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.226446Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.226776Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5388279,
    events_root: None,
}
2023-01-25T06:51:25.226787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-25T06:51:25.226790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::16
2023-01-25T06:51:25.226793Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.226795Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.226797Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [220, 193, 18, 60, 151, 132, 153, 172, 79, 154, 163, 134, 75, 111, 141, 31, 182, 250, 69, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([159, 89, 244, 97, 216, 246, 171, 160, 194, 159, 249, 175, 143, 250, 196, 14, 37, 21, 116, 148]) }
2023-01-25T06:51:25.227475Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17086799,
    events_root: None,
}
2023-01-25T06:51:25.227497Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-25T06:51:25.227501Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::17
2023-01-25T06:51:25.227503Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.227505Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.227508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.227989Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6473251,
    events_root: None,
}
2023-01-25T06:51:25.228003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-25T06:51:25.228006Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::18
2023-01-25T06:51:25.228009Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.228012Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.228014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.228388Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7086505,
    events_root: None,
}
2023-01-25T06:51:25.228400Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-25T06:51:25.228403Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::19
2023-01-25T06:51:25.228405Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.228408Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.228409Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.228634Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3678020,
    events_root: None,
}
2023-01-25T06:51:25.228639Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.228651Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-25T06:51:25.228653Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::20
2023-01-25T06:51:25.228655Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.228658Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.228660Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.229060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6333935,
    events_root: None,
}
2023-01-25T06:51:25.229072Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-25T06:51:25.229075Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::21
2023-01-25T06:51:25.229077Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.229079Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.229081Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.229435Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5395484,
    events_root: None,
}
2023-01-25T06:51:25.229447Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-25T06:51:25.229450Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::22
2023-01-25T06:51:25.229454Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.229456Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.229458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [25, 236, 15, 167, 249, 230, 98, 26, 64, 23, 178, 63, 27, 27, 118, 213, 175, 202, 223, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([145, 39, 57, 40, 244, 97, 114, 211, 157, 178, 230, 42, 204, 136, 110, 218, 94, 3, 133, 15]) }
2023-01-25T06:51:25.230167Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17886808,
    events_root: None,
}
2023-01-25T06:51:25.230189Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-25T06:51:25.230192Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::23
2023-01-25T06:51:25.230195Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.230197Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.230199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.230652Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6479587,
    events_root: None,
}
2023-01-25T06:51:25.230664Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-25T06:51:25.230667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::24
2023-01-25T06:51:25.230670Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.230673Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.230675Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.231113Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7067785,
    events_root: None,
}
2023-01-25T06:51:25.231128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-25T06:51:25.231132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::25
2023-01-25T06:51:25.231134Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.231138Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.231140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.231441Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3665348,
    events_root: None,
}
2023-01-25T06:51:25.231447Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.231464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-25T06:51:25.231469Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::26
2023-01-25T06:51:25.231471Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.231475Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.231477Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.231910Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6311840,
    events_root: None,
}
2023-01-25T06:51:25.231923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-25T06:51:25.231925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::27
2023-01-25T06:51:25.231928Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.231931Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.231932Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.232266Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5376765,
    events_root: None,
}
2023-01-25T06:51:25.232278Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-25T06:51:25.232280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::28
2023-01-25T06:51:25.232282Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.232285Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.232286Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [115, 254, 228, 94, 0, 152, 111, 220, 240, 125, 195, 126, 174, 50, 148, 157, 113, 251, 213, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 33, 73, 89, 43, 117, 95, 36, 123, 177, 163, 118, 200, 201, 50, 148, 185, 37, 107, 154]) }
2023-01-25T06:51:25.233080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18238091,
    events_root: None,
}
2023-01-25T06:51:25.233102Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-25T06:51:25.233105Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::29
2023-01-25T06:51:25.233107Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.233109Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.233111Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.233540Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6466915,
    events_root: None,
}
2023-01-25T06:51:25.233553Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-25T06:51:25.233556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::30
2023-01-25T06:51:25.233558Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.233561Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.233562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.233862Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5636810,
    events_root: None,
}
2023-01-25T06:51:25.233872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-25T06:51:25.233875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::31
2023-01-25T06:51:25.233877Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.233880Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.233882Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.234174Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3711930,
    events_root: None,
}
2023-01-25T06:51:25.234180Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 406,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=539): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.234192Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-25T06:51:25.234195Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::32
2023-01-25T06:51:25.234197Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.234200Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.234201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.234464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3949605,
    events_root: None,
}
2023-01-25T06:51:25.234474Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-25T06:51:25.234477Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::33
2023-01-25T06:51:25.234479Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.234482Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.234483Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.234742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3945790,
    events_root: None,
}
2023-01-25T06:51:25.234751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-25T06:51:25.234754Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::34
2023-01-25T06:51:25.234756Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.234759Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.234760Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [40, 252, 188, 67, 92, 74, 211, 212, 23, 13, 41, 91, 221, 173, 172, 180, 71, 106, 240, 221, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([27, 47, 20, 62, 115, 89, 64, 100, 228, 180, 154, 197, 75, 89, 74, 3, 65, 136, 122, 18]) }
2023-01-25T06:51:25.235488Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18248983,
    events_root: None,
}
2023-01-25T06:51:25.235510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-25T06:51:25.235514Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "revertRetDataSize"::Merge::35
2023-01-25T06:51:25.235516Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
2023-01-25T06:51:25.235518Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-25T06:51:25.235520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.235958Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6513497,
    events_root: None,
}
2023-01-25T06:51:25.238023Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:717.535984ms
2023-01-25T06:51:25.513422Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/subcallReturnMoreThenExpected.json", Total Files :: 1
2023-01-25T06:51:25.543192Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:25.543390Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:25.543394Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:25.543456Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:25.543459Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:25.543526Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:25.543529Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:25.543587Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:25.543660Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T06:51:25.543664Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subcallReturnMoreThenExpected"::Istanbul::0
2023-01-25T06:51:25.543667Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/subcallReturnMoreThenExpected.json"
2023-01-25T06:51:25.543672Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:25.543674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.909088Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3607057,
    events_root: None,
}
2023-01-25T06:51:25.909105Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 6,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 401,
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
                        value: 35,
                    },
                    message: "ABORT(pc=175): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.909131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T06:51:25.909138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subcallReturnMoreThenExpected"::Berlin::0
2023-01-25T06:51:25.909141Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/subcallReturnMoreThenExpected.json"
2023-01-25T06:51:25.909144Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:25.909145Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.909405Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3607057,
    events_root: None,
}
2023-01-25T06:51:25.909413Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 6,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 401,
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
                        value: 35,
                    },
                    message: "ABORT(pc=175): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.909432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:25.909434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subcallReturnMoreThenExpected"::London::0
2023-01-25T06:51:25.909436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/subcallReturnMoreThenExpected.json"
2023-01-25T06:51:25.909439Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:25.909440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.909671Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3607057,
    events_root: None,
}
2023-01-25T06:51:25.909678Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 6,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 401,
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
                        value: 35,
                    },
                    message: "ABORT(pc=175): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.909697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:25.909700Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subcallReturnMoreThenExpected"::Merge::0
2023-01-25T06:51:25.909702Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/subcallReturnMoreThenExpected.json"
2023-01-25T06:51:25.909705Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T06:51:25.909706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:25.909936Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3607057,
    events_root: None,
}
2023-01-25T06:51:25.909942Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 6,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 401,
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
                        value: 35,
                    },
                    message: "ABORT(pc=175): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:25.911571Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.77472ms
2023-01-25T06:51:26.177744Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json", Total Files :: 1
2023-01-25T06:51:26.267210Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T06:51:26.267404Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:26.267408Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T06:51:26.267499Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:26.267503Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T06:51:26.267620Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:26.267624Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T06:51:26.267729Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T06:51:26.267863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T06:51:26.267869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::1
2023-01-25T06:51:26.267874Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.267879Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.267882Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.636227Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3144889,
    events_root: None,
}
2023-01-25T06:51:26.636244Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.636261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-25T06:51:26.636268Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::4
2023-01-25T06:51:26.636270Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.636273Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.636275Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.636503Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 4077633,
    events_root: None,
}
2023-01-25T06:51:26.636509Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 0 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.636525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-25T06:51:26.636528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::6
2023-01-25T06:51:26.636530Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.636532Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.636534Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.636742Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 4077633,
    events_root: None,
}
2023-01-25T06:51:26.636748Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 1 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.636763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-25T06:51:26.636766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::8
2023-01-25T06:51:26.636768Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.636770Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.636772Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.636979Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 4077633,
    events_root: None,
}
2023-01-25T06:51:26.636984Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 9 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.636998Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-25T06:51:26.637001Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::9
2023-01-25T06:51:26.637003Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.637007Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.637008Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.637257Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 4077729,
    events_root: None,
}
2023-01-25T06:51:26.637262Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 16 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.637276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-25T06:51:26.637279Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::10
2023-01-25T06:51:26.637280Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.637283Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.637284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.637494Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 4077729,
    events_root: None,
}
2023-01-25T06:51:26.637500Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 16 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.637514Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-25T06:51:26.637516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::11
2023-01-25T06:51:26.637519Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.637521Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.637523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.637730Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 4077801,
    events_root: None,
}
2023-01-25T06:51:26.637736Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy start 32 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.637750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-25T06:51:26.637753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::13
2023-01-25T06:51:26.637755Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.637758Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.637759Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.637957Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3186710,
    events_root: None,
}
2023-01-25T06:51:26.637963Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.637977Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-25T06:51:26.637979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::16
2023-01-25T06:51:26.637981Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.637985Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.637986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.638188Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3200780,
    events_root: None,
}
2023-01-25T06:51:26.638194Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 0 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.638209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-25T06:51:26.638212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::18
2023-01-25T06:51:26.638214Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.638217Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.638218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.638451Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3200780,
    events_root: None,
}
2023-01-25T06:51:26.638457Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 1 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.638472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-25T06:51:26.638474Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::20
2023-01-25T06:51:26.638476Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.638479Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.638480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.638684Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3200780,
    events_root: None,
}
2023-01-25T06:51:26.638689Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 9 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.638703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-25T06:51:26.638705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::21
2023-01-25T06:51:26.638707Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.638710Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.638711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.638910Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3200876,
    events_root: None,
}
2023-01-25T06:51:26.638915Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 16 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.638929Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-25T06:51:26.638931Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::22
2023-01-25T06:51:26.638933Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.638936Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.638938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.639134Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3200876,
    events_root: None,
}
2023-01-25T06:51:26.639140Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 16 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.639154Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-25T06:51:26.639157Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::23
2023-01-25T06:51:26.639159Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.639161Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.639163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.639358Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3200948,
    events_root: None,
}
2023-01-25T06:51:26.639363Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy start 32 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.639377Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T06:51:26.639380Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::0
2023-01-25T06:51:26.639382Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.639385Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.639386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.639793Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6429731,
    events_root: None,
}
2023-01-25T06:51:26.639810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-25T06:51:26.639812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::2
2023-01-25T06:51:26.639815Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.639818Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.639820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.640189Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6464296,
    events_root: None,
}
2023-01-25T06:51:26.640205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-25T06:51:26.640208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::3
2023-01-25T06:51:26.640210Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.640212Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.640214Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.640558Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5571821,
    events_root: None,
}
2023-01-25T06:51:26.640573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-25T06:51:26.640577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::5
2023-01-25T06:51:26.640579Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.640581Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.640583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.640924Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5571821,
    events_root: None,
}
2023-01-25T06:51:26.640939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-25T06:51:26.640942Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::7
2023-01-25T06:51:26.640944Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.640946Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.640948Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.641291Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5571818,
    events_root: None,
}
2023-01-25T06:51:26.641306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-25T06:51:26.641308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::12
2023-01-25T06:51:26.641311Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.641313Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.641315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.641661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5575141,
    events_root: None,
}
2023-01-25T06:51:26.641677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-25T06:51:26.641679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::14
2023-01-25T06:51:26.641682Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.641684Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.641686Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.642034Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5587444,
    events_root: None,
}
2023-01-25T06:51:26.642048Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-25T06:51:26.642051Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::15
2023-01-25T06:51:26.642053Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.642056Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.642057Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.642427Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5587447,
    events_root: None,
}
2023-01-25T06:51:26.642444Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-25T06:51:26.642447Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::17
2023-01-25T06:51:26.642449Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.642452Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.642453Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.642800Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5587447,
    events_root: None,
}
2023-01-25T06:51:26.642816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-25T06:51:26.642819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::London::19
2023-01-25T06:51:26.642821Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.642823Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.642825Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.643172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5587444,
    events_root: None,
}
2023-01-25T06:51:26.643187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T06:51:26.643190Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::1
2023-01-25T06:51:26.643192Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.643195Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.643197Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.643403Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 4083073,
    events_root: None,
}
2023-01-25T06:51:26.643408Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.643424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-25T06:51:26.643426Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::4
2023-01-25T06:51:26.643429Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.643431Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.643433Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.643628Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3208833,
    events_root: None,
}
2023-01-25T06:51:26.643634Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 0 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.643645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-25T06:51:26.643647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::6
2023-01-25T06:51:26.643649Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.643653Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.643654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.643851Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3208833,
    events_root: None,
}
2023-01-25T06:51:26.643856Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 1 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.643867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-25T06:51:26.643869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::8
2023-01-25T06:51:26.643871Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.643874Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.643875Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.644079Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3208833,
    events_root: None,
}
2023-01-25T06:51:26.644084Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 9 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.644096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-25T06:51:26.644099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::9
2023-01-25T06:51:26.644100Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.644103Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.644104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.644336Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3208929,
    events_root: None,
}
2023-01-25T06:51:26.644341Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 16 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.644352Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-25T06:51:26.644355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::10
2023-01-25T06:51:26.644357Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.644359Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.644361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.644563Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3208929,
    events_root: None,
}
2023-01-25T06:51:26.644569Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 16 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.644581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-25T06:51:26.644583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::11
2023-01-25T06:51:26.644585Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.644588Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.644589Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.644785Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3209001,
    events_root: None,
}
2023-01-25T06:51:26.644791Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy start 32 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.644801Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-25T06:51:26.644804Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::13
2023-01-25T06:51:26.644806Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.644808Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.644810Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.645007Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3207469,
    events_root: None,
}
2023-01-25T06:51:26.645012Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.645025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-25T06:51:26.645028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::16
2023-01-25T06:51:26.645030Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.645032Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.645034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.645240Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3224459,
    events_root: None,
}
2023-01-25T06:51:26.645245Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 0 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.645260Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-25T06:51:26.645262Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::18
2023-01-25T06:51:26.645264Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.645266Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.645268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.645502Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3224459,
    events_root: None,
}
2023-01-25T06:51:26.645508Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 1 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.645521Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-25T06:51:26.645524Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::20
2023-01-25T06:51:26.645526Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.645528Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.645530Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.645732Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3224459,
    events_root: None,
}
2023-01-25T06:51:26.645738Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 9 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.645752Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-25T06:51:26.645754Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::21
2023-01-25T06:51:26.645756Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.645760Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.645761Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.645961Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3224555,
    events_root: None,
}
2023-01-25T06:51:26.645967Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 16 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.645982Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-25T06:51:26.645985Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::22
2023-01-25T06:51:26.645987Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.645989Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.645991Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.646190Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3224555,
    events_root: None,
}
2023-01-25T06:51:26.646195Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy end 16 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.646209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-25T06:51:26.646211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::23
2023-01-25T06:51:26.646214Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.646217Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.646218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.646438Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 3224627,
    events_root: None,
}
2023-01-25T06:51:26.646444Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=35): returndatacopy start 32 exceeds return-data length 16",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-25T06:51:26.646457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T06:51:26.646460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::0
2023-01-25T06:51:26.646463Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.646465Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.646467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.646831Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6450745,
    events_root: None,
}
2023-01-25T06:51:26.646848Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-25T06:51:26.646851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::2
2023-01-25T06:51:26.646853Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.646856Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.646857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.647216Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6464296,
    events_root: None,
}
2023-01-25T06:51:26.647231Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-25T06:51:26.647234Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::3
2023-01-25T06:51:26.647236Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.647239Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.647240Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.647587Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5571821,
    events_root: None,
}
2023-01-25T06:51:26.647602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-25T06:51:26.647605Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::5
2023-01-25T06:51:26.647607Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.647609Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.647611Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.647964Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5571821,
    events_root: None,
}
2023-01-25T06:51:26.647979Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-25T06:51:26.647982Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::7
2023-01-25T06:51:26.647985Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.647988Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.647990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.648340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5571818,
    events_root: None,
}
2023-01-25T06:51:26.648356Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-25T06:51:26.648360Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::12
2023-01-25T06:51:26.648362Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.648365Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.648366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.648714Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5575141,
    events_root: None,
}
2023-01-25T06:51:26.648731Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-25T06:51:26.648733Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::14
2023-01-25T06:51:26.648736Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.648738Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.648739Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.649128Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5587444,
    events_root: None,
}
2023-01-25T06:51:26.649143Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-25T06:51:26.649146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::15
2023-01-25T06:51:26.649149Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.649151Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.649154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.649504Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5587447,
    events_root: None,
}
2023-01-25T06:51:26.649520Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-25T06:51:26.649523Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::17
2023-01-25T06:51:26.649525Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.649528Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.649529Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.649876Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5587447,
    events_root: None,
}
2023-01-25T06:51:26.649892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-25T06:51:26.649895Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tooLongReturnDataCopy"::Merge::19
2023-01-25T06:51:26.649897Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stReturnDataTest/tooLongReturnDataCopy.json"
2023-01-25T06:51:26.649900Z  INFO evm_eth_compliance::statetest::runner: TX len : 132
2023-01-25T06:51:26.649901Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T06:51:26.650252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5587444,
    events_root: None,
}
2023-01-25T06:51:26.651998Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.062243ms
```
