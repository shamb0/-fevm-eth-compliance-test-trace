> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/VMTests/vmTests

> For Review

* Execution looks OK. No error observed

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/VMTests/vmTests \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-24T06:35:10.877961Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/VMTests/vmTests", Total Files :: 11
2023-01-24T06:35:10.878205Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:10.908016Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:10.908222Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:10.908227Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:10.908283Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:10.908286Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:10.908346Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:10.908349Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:10.908406Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:10.908408Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:10.908459Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:10.908461Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T06:35:10.908527Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:10.908529Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T06:35:10.908588Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:10.908661Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:10.908665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Istanbul::0
2023-01-24T06:35:10.908669Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:10.908672Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:10.908673Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.292232Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3027597,
    events_root: None,
}
2023-01-24T06:35:11.292259Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:11.292267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Istanbul::1
2023-01-24T06:35:11.292270Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.292274Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.292276Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.292496Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4048181,
    events_root: None,
}
2023-01-24T06:35:11.292507Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:11.292511Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Istanbul::2
2023-01-24T06:35:11.292514Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.292517Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.292519Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.292716Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3957591,
    events_root: None,
}
2023-01-24T06:35:11.292727Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:35:11.292730Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Istanbul::3
2023-01-24T06:35:11.292733Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.292736Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.292739Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.292918Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042189,
    events_root: None,
}
2023-01-24T06:35:11.292928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:35:11.292932Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Istanbul::4
2023-01-24T06:35:11.292934Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.292938Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.292940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.293119Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042177,
    events_root: None,
}
2023-01-24T06:35:11.293130Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:11.293134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Berlin::0
2023-01-24T06:35:11.293137Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.293142Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.293145Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.293329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3027597,
    events_root: None,
}
2023-01-24T06:35:11.293339Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:11.293342Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Berlin::1
2023-01-24T06:35:11.293345Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.293347Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.293349Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.293612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4067319,
    events_root: None,
}
2023-01-24T06:35:11.293641Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:11.293650Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Berlin::2
2023-01-24T06:35:11.293658Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.293666Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.293670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.293856Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3056837,
    events_root: None,
}
2023-01-24T06:35:11.293867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:35:11.293870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Berlin::3
2023-01-24T06:35:11.293874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.293878Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.293880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.294076Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042189,
    events_root: None,
}
2023-01-24T06:35:11.294087Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:35:11.294090Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Berlin::4
2023-01-24T06:35:11.294093Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.294096Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.294098Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.294280Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042177,
    events_root: None,
}
2023-01-24T06:35:11.294290Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:11.294294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::London::0
2023-01-24T06:35:11.294297Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.294301Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.294303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.294477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3027597,
    events_root: None,
}
2023-01-24T06:35:11.294489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:11.294492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::London::1
2023-01-24T06:35:11.294495Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.294499Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.294501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.294697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4067319,
    events_root: None,
}
2023-01-24T06:35:11.294708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:11.294711Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::London::2
2023-01-24T06:35:11.294714Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.294717Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.294720Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.294900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3056837,
    events_root: None,
}
2023-01-24T06:35:11.294912Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:35:11.294916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::London::3
2023-01-24T06:35:11.294919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.294922Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.294925Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.295101Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042189,
    events_root: None,
}
2023-01-24T06:35:11.295111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:35:11.295114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::London::4
2023-01-24T06:35:11.295118Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.295122Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.295123Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.295360Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042177,
    events_root: None,
}
2023-01-24T06:35:11.295386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:11.295390Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Merge::0
2023-01-24T06:35:11.295392Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.295395Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.295397Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.295577Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3027597,
    events_root: None,
}
2023-01-24T06:35:11.295588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:11.295592Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Merge::1
2023-01-24T06:35:11.295594Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.295598Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.295600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.295795Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4067319,
    events_root: None,
}
2023-01-24T06:35:11.295806Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:11.295809Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Merge::2
2023-01-24T06:35:11.295812Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.295815Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.295817Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.295997Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3056837,
    events_root: None,
}
2023-01-24T06:35:11.296007Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:35:11.296012Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Merge::3
2023-01-24T06:35:11.296015Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.296018Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.296021Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.296201Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042189,
    events_root: None,
}
2023-01-24T06:35:11.296211Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:35:11.296215Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "blockInfo"::Merge::4
2023-01-24T06:35:11.296218Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.296221Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.296223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.296398Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042177,
    events_root: None,
}
2023-01-24T06:35:11.298001Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/blockInfo.json"
2023-01-24T06:35:11.298034Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.324284Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:11.324394Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324399Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:11.324453Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324456Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:11.324516Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324518Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:11.324574Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324576Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:11.324625Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324628Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T06:35:11.324692Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324694Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T06:35:11.324753Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324756Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T06:35:11.324801Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324804Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T06:35:11.324849Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324851Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T06:35:11.324916Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.324993Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:11.324999Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Istanbul::0
2023-01-24T06:35:11.325003Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.325007Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.325009Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.664051Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5056735,
    events_root: None,
}
2023-01-24T06:35:11.664075Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:11.664081Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Istanbul::1
2023-01-24T06:35:11.664084Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.664087Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.664088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.664317Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5075556,
    events_root: None,
}
2023-01-24T06:35:11.664327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:11.664329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Istanbul::2
2023-01-24T06:35:11.664332Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.664334Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.664336Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.664532Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035216,
    events_root: None,
}
2023-01-24T06:35:11.664541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:35:11.664544Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Istanbul::3
2023-01-24T06:35:11.664546Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.664548Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.664551Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.664730Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3117922,
    events_root: None,
}
2023-01-24T06:35:11.664740Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:35:11.664742Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Istanbul::4
2023-01-24T06:35:11.664744Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.664747Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.664748Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.664933Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130470,
    events_root: None,
}
2023-01-24T06:35:11.664941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T06:35:11.664944Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Istanbul::5
2023-01-24T06:35:11.664946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.664948Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.664950Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.665127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3119400,
    events_root: None,
}
2023-01-24T06:35:11.665135Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T06:35:11.665138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Istanbul::6
2023-01-24T06:35:11.665140Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.665142Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.665144Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.665336Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124363,
    events_root: None,
}
2023-01-24T06:35:11.665346Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T06:35:11.665348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Istanbul::7
2023-01-24T06:35:11.665350Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.665353Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.665354Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.665549Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4042057,
    events_root: None,
}
2023-01-24T06:35:11.665560Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:11.665563Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Berlin::0
2023-01-24T06:35:11.665565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.665567Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.665569Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.665763Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4119816,
    events_root: None,
}
2023-01-24T06:35:11.665775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:11.665778Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Berlin::1
2023-01-24T06:35:11.665780Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.665782Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.665784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.665983Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4138637,
    events_root: None,
}
2023-01-24T06:35:11.665994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:11.665997Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Berlin::2
2023-01-24T06:35:11.665999Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.666001Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.666003Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.666193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035216,
    events_root: None,
}
2023-01-24T06:35:11.666205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:35:11.666207Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Berlin::3
2023-01-24T06:35:11.666209Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.666212Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.666213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.666387Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3117922,
    events_root: None,
}
2023-01-24T06:35:11.666395Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:35:11.666398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Berlin::4
2023-01-24T06:35:11.666400Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.666402Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.666404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.666579Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130470,
    events_root: None,
}
2023-01-24T06:35:11.666588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T06:35:11.666591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Berlin::5
2023-01-24T06:35:11.666593Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.666595Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.666597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.666770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3119400,
    events_root: None,
}
2023-01-24T06:35:11.666779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T06:35:11.666781Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Berlin::6
2023-01-24T06:35:11.666784Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.666786Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.666787Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.666970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124363,
    events_root: None,
}
2023-01-24T06:35:11.666979Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T06:35:11.666981Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Berlin::7
2023-01-24T06:35:11.666983Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.666986Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.666987Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.667166Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3137679,
    events_root: None,
}
2023-01-24T06:35:11.667176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:11.667178Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::London::0
2023-01-24T06:35:11.667180Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.667183Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.667184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.667377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4119816,
    events_root: None,
}
2023-01-24T06:35:11.667389Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:11.667391Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::London::1
2023-01-24T06:35:11.667393Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.667396Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.667397Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.667592Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4138637,
    events_root: None,
}
2023-01-24T06:35:11.667605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:11.667607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::London::2
2023-01-24T06:35:11.667609Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.667612Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.667613Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.667803Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035216,
    events_root: None,
}
2023-01-24T06:35:11.667814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:35:11.667817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::London::3
2023-01-24T06:35:11.667819Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.667821Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.667823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.668006Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3117922,
    events_root: None,
}
2023-01-24T06:35:11.668014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:35:11.668017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::London::4
2023-01-24T06:35:11.668018Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.668021Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.668022Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.668199Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130470,
    events_root: None,
}
2023-01-24T06:35:11.668207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T06:35:11.668210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::London::5
2023-01-24T06:35:11.668213Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.668216Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.668218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.668392Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3119400,
    events_root: None,
}
2023-01-24T06:35:11.668402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T06:35:11.668405Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::London::6
2023-01-24T06:35:11.668407Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.668409Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.668411Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.668589Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124363,
    events_root: None,
}
2023-01-24T06:35:11.668597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T06:35:11.668600Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::London::7
2023-01-24T06:35:11.668602Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.668604Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.668606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.668784Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3137679,
    events_root: None,
}
2023-01-24T06:35:11.668793Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:11.668796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Merge::0
2023-01-24T06:35:11.668798Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.668800Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.668801Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.668998Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4119816,
    events_root: None,
}
2023-01-24T06:35:11.669011Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:11.669013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Merge::1
2023-01-24T06:35:11.669015Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.669018Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.669019Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.669213Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4138637,
    events_root: None,
}
2023-01-24T06:35:11.669224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:11.669227Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Merge::2
2023-01-24T06:35:11.669229Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.669231Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.669233Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.669427Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035216,
    events_root: None,
}
2023-01-24T06:35:11.669439Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:35:11.669442Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Merge::3
2023-01-24T06:35:11.669444Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.669446Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.669448Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.669621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3117922,
    events_root: None,
}
2023-01-24T06:35:11.669629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:35:11.669632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Merge::4
2023-01-24T06:35:11.669634Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.669636Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.669638Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.669815Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130470,
    events_root: None,
}
2023-01-24T06:35:11.669823Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T06:35:11.669826Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Merge::5
2023-01-24T06:35:11.669828Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.669830Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.669832Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.670011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3119400,
    events_root: None,
}
2023-01-24T06:35:11.670019Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T06:35:11.670022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Merge::6
2023-01-24T06:35:11.670024Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.670026Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.670028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.670206Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124363,
    events_root: None,
}
2023-01-24T06:35:11.670215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T06:35:11.670217Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopy"::Merge::7
2023-01-24T06:35:11.670220Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.670222Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.670223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:11.670401Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3137679,
    events_root: None,
}
2023-01-24T06:35:11.671768Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatacopy.json"
2023-01-24T06:35:11.671795Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:11.696965Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:11.697072Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.697076Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:11.697136Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.697139Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:11.697200Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.697203Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:11.697272Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.697275Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:11.697327Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.697330Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T06:35:11.697397Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.697399Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T06:35:11.697457Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.697459Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T06:35:11.697507Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:11.697580Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:11.697586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::Istanbul::0
2023-01-24T06:35:11.697589Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:11.697594Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:11.697596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.033315Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5542313,
    events_root: None,
}
2023-01-24T06:35:12.033341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:12.033348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::Istanbul::1
2023-01-24T06:35:12.033351Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.033355Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.033357Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.033656Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5544708,
    events_root: None,
}
2023-01-24T06:35:12.033670Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:12.033674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::Istanbul::2
2023-01-24T06:35:12.033677Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.033681Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.033683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.033990Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5547038,
    events_root: None,
}
2023-01-24T06:35:12.034003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:12.034008Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::Berlin::0
2023-01-24T06:35:12.034011Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.034014Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.034016Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.034287Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4603191,
    events_root: None,
}
2023-01-24T06:35:12.034300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:12.034304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::Berlin::1
2023-01-24T06:35:12.034306Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.034310Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.034312Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.034587Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4606085,
    events_root: None,
}
2023-01-24T06:35:12.034600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:12.034605Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::Berlin::2
2023-01-24T06:35:12.034608Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.034612Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.034614Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.034900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4608416,
    events_root: None,
}
2023-01-24T06:35:12.034913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:12.034916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::London::0
2023-01-24T06:35:12.034919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.034923Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.034925Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.035229Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4603191,
    events_root: None,
}
2023-01-24T06:35:12.035243Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:12.035246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::London::1
2023-01-24T06:35:12.035249Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.035253Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.035255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.035543Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4606085,
    events_root: None,
}
2023-01-24T06:35:12.035556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:12.035560Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::London::2
2023-01-24T06:35:12.035564Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.035567Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.035569Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.035834Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4608416,
    events_root: None,
}
2023-01-24T06:35:12.035847Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:12.035850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::Merge::0
2023-01-24T06:35:12.035853Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.035857Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.035859Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.036123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4603191,
    events_root: None,
}
2023-01-24T06:35:12.036136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:12.036139Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::Merge::1
2023-01-24T06:35:12.036142Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.036145Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.036147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.036413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4606085,
    events_root: None,
}
2023-01-24T06:35:12.036426Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:12.036430Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataload"::Merge::2
2023-01-24T06:35:12.036433Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.036436Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.036438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.036704Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4608416,
    events_root: None,
}
2023-01-24T06:35:12.038374Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldataload.json"
2023-01-24T06:35:12.038408Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.064710Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:12.064876Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.064880Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:12.064939Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.064942Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:12.065005Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.065081Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:12.065087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::0
2023-01-24T06:35:12.065091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.065096Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.065098Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.442813Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4019952,
    events_root: None,
}
2023-01-24T06:35:12.442837Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T06:35:12.442844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::5
2023-01-24T06:35:12.442847Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.442851Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.442854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.443061Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123362,
    events_root: None,
}
2023-01-24T06:35:12.443071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-24T06:35:12.443075Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::10
2023-01-24T06:35:12.443080Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.443084Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.443086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.443277Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123395,
    events_root: None,
}
2023-01-24T06:35:12.443287Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-24T06:35:12.443290Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::15
2023-01-24T06:35:12.443293Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.443297Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.443298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.443486Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123428,
    events_root: None,
}
2023-01-24T06:35:12.443496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:12.443499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::1
2023-01-24T06:35:12.443503Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.443507Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.443509Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.443712Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4032426,
    events_root: None,
}
2023-01-24T06:35:12.443723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T06:35:12.443726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::6
2023-01-24T06:35:12.443729Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.443732Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.443734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.443924Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123536,
    events_root: None,
}
2023-01-24T06:35:12.443934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-24T06:35:12.443937Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::11
2023-01-24T06:35:12.443941Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.443945Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.443947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.444137Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123569,
    events_root: None,
}
2023-01-24T06:35:12.444148Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 16
2023-01-24T06:35:12.444151Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::16
2023-01-24T06:35:12.444154Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.444157Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.444159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.444345Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123602,
    events_root: None,
}
2023-01-24T06:35:12.444357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:12.444360Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::2
2023-01-24T06:35:12.444363Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.444366Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.444368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.444569Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4033892,
    events_root: None,
}
2023-01-24T06:35:12.444581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T06:35:12.444585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::7
2023-01-24T06:35:12.444587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.444591Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.444593Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.444782Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125003,
    events_root: None,
}
2023-01-24T06:35:12.444792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-24T06:35:12.444795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::12
2023-01-24T06:35:12.444798Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.444803Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.444805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.445008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125036,
    events_root: None,
}
2023-01-24T06:35:12.445018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 17
2023-01-24T06:35:12.445021Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::17
2023-01-24T06:35:12.445025Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.445030Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.445031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.445218Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125069,
    events_root: None,
}
2023-01-24T06:35:12.445228Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:35:12.445232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::3
2023-01-24T06:35:12.445235Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.445238Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.445241Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.445450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035602,
    events_root: None,
}
2023-01-24T06:35:12.445461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-24T06:35:12.445464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::8
2023-01-24T06:35:12.445468Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.445471Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.445475Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.445678Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124868,
    events_root: None,
}
2023-01-24T06:35:12.445689Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-24T06:35:12.445692Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::13
2023-01-24T06:35:12.445695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.445700Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.445702Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.445887Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124901,
    events_root: None,
}
2023-01-24T06:35:12.445897Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 18
2023-01-24T06:35:12.445901Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::18
2023-01-24T06:35:12.445903Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.445906Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.445908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.446095Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124934,
    events_root: None,
}
2023-01-24T06:35:12.446105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:35:12.446108Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::4
2023-01-24T06:35:12.446111Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.446114Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.446117Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.446324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4049395,
    events_root: None,
}
2023-01-24T06:35:12.446335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-24T06:35:12.446338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::9
2023-01-24T06:35:12.446340Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.446344Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.446346Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.446536Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131149,
    events_root: None,
}
2023-01-24T06:35:12.446546Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-24T06:35:12.446549Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::14
2023-01-24T06:35:12.446552Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.446555Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.446558Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.446748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131182,
    events_root: None,
}
2023-01-24T06:35:12.446759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 19
2023-01-24T06:35:12.446762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Istanbul::19
2023-01-24T06:35:12.446764Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.446768Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.446770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.446957Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131215,
    events_root: None,
}
2023-01-24T06:35:12.446968Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:12.446972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::0
2023-01-24T06:35:12.446975Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.446978Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.446980Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.447182Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4032851,
    events_root: None,
}
2023-01-24T06:35:12.447193Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T06:35:12.447197Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::5
2023-01-24T06:35:12.447200Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.447203Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.447206Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.447393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123362,
    events_root: None,
}
2023-01-24T06:35:12.447404Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-24T06:35:12.447407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::10
2023-01-24T06:35:12.447411Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.447414Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.447416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.447606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123395,
    events_root: None,
}
2023-01-24T06:35:12.447616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-24T06:35:12.447619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::15
2023-01-24T06:35:12.447622Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.447625Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.447627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.447814Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123428,
    events_root: None,
}
2023-01-24T06:35:12.447825Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:12.447828Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::1
2023-01-24T06:35:12.447832Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.447836Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.447838Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.448057Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4032426,
    events_root: None,
}
2023-01-24T06:35:12.448070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T06:35:12.448073Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::6
2023-01-24T06:35:12.448075Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.448079Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.448080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.448324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123536,
    events_root: None,
}
2023-01-24T06:35:12.448336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-24T06:35:12.448340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::11
2023-01-24T06:35:12.448343Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.448346Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.448348Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.448612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123569,
    events_root: None,
}
2023-01-24T06:35:12.448625Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-24T06:35:12.448629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::16
2023-01-24T06:35:12.448631Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.448634Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.448636Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.448898Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123602,
    events_root: None,
}
2023-01-24T06:35:12.448911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:12.448915Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::2
2023-01-24T06:35:12.448919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.448922Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.448924Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.449159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4033892,
    events_root: None,
}
2023-01-24T06:35:12.449168Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T06:35:12.449171Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::7
2023-01-24T06:35:12.449173Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.449176Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.449177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.449389Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125003,
    events_root: None,
}
2023-01-24T06:35:12.449399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-24T06:35:12.449402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::12
2023-01-24T06:35:12.449404Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.449407Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.449409Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.449600Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125036,
    events_root: None,
}
2023-01-24T06:35:12.449609Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-24T06:35:12.449612Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::17
2023-01-24T06:35:12.449614Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.449616Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.449618Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.449799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125069,
    events_root: None,
}
2023-01-24T06:35:12.449808Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:35:12.449811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::3
2023-01-24T06:35:12.449814Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.449817Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.449819Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.450016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035602,
    events_root: None,
}
2023-01-24T06:35:12.450025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-24T06:35:12.450028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::8
2023-01-24T06:35:12.450030Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.450033Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.450034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.450220Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124868,
    events_root: None,
}
2023-01-24T06:35:12.450230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-24T06:35:12.450232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::13
2023-01-24T06:35:12.450234Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.450237Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.450238Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.450422Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124901,
    events_root: None,
}
2023-01-24T06:35:12.450431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-24T06:35:12.450434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::18
2023-01-24T06:35:12.450436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.450438Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.450440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.450621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124934,
    events_root: None,
}
2023-01-24T06:35:12.450630Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:35:12.450632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::4
2023-01-24T06:35:12.450634Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.450638Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.450640Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.450836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4049395,
    events_root: None,
}
2023-01-24T06:35:12.450846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-24T06:35:12.450848Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::9
2023-01-24T06:35:12.450850Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.450853Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.450855Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.451042Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131149,
    events_root: None,
}
2023-01-24T06:35:12.451050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-24T06:35:12.451053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::14
2023-01-24T06:35:12.451055Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.451058Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.451059Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.451242Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131182,
    events_root: None,
}
2023-01-24T06:35:12.451251Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-24T06:35:12.451253Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Berlin::19
2023-01-24T06:35:12.451256Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.451258Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.451260Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.451442Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131215,
    events_root: None,
}
2023-01-24T06:35:12.451451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:12.451454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::0
2023-01-24T06:35:12.451456Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.451458Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.451461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.451657Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4032851,
    events_root: None,
}
2023-01-24T06:35:12.451666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T06:35:12.451669Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::5
2023-01-24T06:35:12.451671Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.451673Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.451675Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.451860Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123362,
    events_root: None,
}
2023-01-24T06:35:12.451869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-24T06:35:12.451872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::10
2023-01-24T06:35:12.451874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.451876Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.451878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.452060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123395,
    events_root: None,
}
2023-01-24T06:35:12.452069Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-24T06:35:12.452071Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::15
2023-01-24T06:35:12.452074Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.452077Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.452078Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.452260Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123428,
    events_root: None,
}
2023-01-24T06:35:12.452269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:12.452272Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::1
2023-01-24T06:35:12.452275Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.452278Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.452280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.452476Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4032426,
    events_root: None,
}
2023-01-24T06:35:12.452485Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T06:35:12.452487Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::6
2023-01-24T06:35:12.452490Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.452492Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.452494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.452686Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123536,
    events_root: None,
}
2023-01-24T06:35:12.452696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-24T06:35:12.452698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::11
2023-01-24T06:35:12.452700Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.452703Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.452705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.452887Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123569,
    events_root: None,
}
2023-01-24T06:35:12.452896Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-24T06:35:12.452899Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::16
2023-01-24T06:35:12.452901Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.452904Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.452905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.453085Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123602,
    events_root: None,
}
2023-01-24T06:35:12.453094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:12.453096Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::2
2023-01-24T06:35:12.453098Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.453101Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.453102Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.453315Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4033892,
    events_root: None,
}
2023-01-24T06:35:12.453325Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T06:35:12.453327Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::7
2023-01-24T06:35:12.453329Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.453333Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.453334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.453518Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125003,
    events_root: None,
}
2023-01-24T06:35:12.453527Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-24T06:35:12.453530Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::12
2023-01-24T06:35:12.453532Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.453534Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.453536Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.453717Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125036,
    events_root: None,
}
2023-01-24T06:35:12.453726Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-24T06:35:12.453729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::17
2023-01-24T06:35:12.453730Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.453733Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.453734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.453912Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125069,
    events_root: None,
}
2023-01-24T06:35:12.453921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:35:12.453924Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::3
2023-01-24T06:35:12.453926Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.453928Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.453931Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.454125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035602,
    events_root: None,
}
2023-01-24T06:35:12.454134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-24T06:35:12.454137Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::8
2023-01-24T06:35:12.454139Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.454142Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.454143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.454329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124868,
    events_root: None,
}
2023-01-24T06:35:12.454341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-24T06:35:12.454343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::13
2023-01-24T06:35:12.454345Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.454348Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.454350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.454533Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124901,
    events_root: None,
}
2023-01-24T06:35:12.454543Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-24T06:35:12.454546Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::18
2023-01-24T06:35:12.454548Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.454551Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.454552Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.454733Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124934,
    events_root: None,
}
2023-01-24T06:35:12.454742Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:35:12.454744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::4
2023-01-24T06:35:12.454746Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.454749Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.454750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.454949Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4049395,
    events_root: None,
}
2023-01-24T06:35:12.454958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-24T06:35:12.454961Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::9
2023-01-24T06:35:12.454963Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.454965Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.454966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.455152Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131149,
    events_root: None,
}
2023-01-24T06:35:12.455162Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-24T06:35:12.455164Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::14
2023-01-24T06:35:12.455166Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.455169Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.455170Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.455354Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131182,
    events_root: None,
}
2023-01-24T06:35:12.455363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-24T06:35:12.455366Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::London::19
2023-01-24T06:35:12.455367Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.455371Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.455372Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.455552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131215,
    events_root: None,
}
2023-01-24T06:35:12.455561Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:12.455564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::0
2023-01-24T06:35:12.455566Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.455568Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.455570Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.455798Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4032851,
    events_root: None,
}
2023-01-24T06:35:12.455812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T06:35:12.455816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::5
2023-01-24T06:35:12.455819Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.455822Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.455824Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.456096Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123362,
    events_root: None,
}
2023-01-24T06:35:12.456110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-24T06:35:12.456114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::10
2023-01-24T06:35:12.456117Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.456120Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.456123Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.456342Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123395,
    events_root: None,
}
2023-01-24T06:35:12.456352Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-24T06:35:12.456354Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::15
2023-01-24T06:35:12.456356Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.456359Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.456360Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.456544Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123428,
    events_root: None,
}
2023-01-24T06:35:12.456554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:12.456557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::1
2023-01-24T06:35:12.456559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.456561Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.456563Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.456757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4032426,
    events_root: None,
}
2023-01-24T06:35:12.456767Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T06:35:12.456769Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::6
2023-01-24T06:35:12.456771Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.456775Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.456777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.456959Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123536,
    events_root: None,
}
2023-01-24T06:35:12.456968Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-24T06:35:12.456970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::11
2023-01-24T06:35:12.456972Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.456975Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.456976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.457159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123569,
    events_root: None,
}
2023-01-24T06:35:12.457168Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-24T06:35:12.457170Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::16
2023-01-24T06:35:12.457173Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.457175Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.457177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.457365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3123602,
    events_root: None,
}
2023-01-24T06:35:12.457376Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:12.457378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::2
2023-01-24T06:35:12.457380Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.457383Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.457385Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.457580Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4033892,
    events_root: None,
}
2023-01-24T06:35:12.457590Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T06:35:12.457592Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::7
2023-01-24T06:35:12.457594Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.457598Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.457599Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.457781Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125003,
    events_root: None,
}
2023-01-24T06:35:12.457790Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-24T06:35:12.457793Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::12
2023-01-24T06:35:12.457795Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.457798Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.457799Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.457979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125036,
    events_root: None,
}
2023-01-24T06:35:12.457989Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-24T06:35:12.457991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::17
2023-01-24T06:35:12.457994Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.457997Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.457998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.458179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3125069,
    events_root: None,
}
2023-01-24T06:35:12.458188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:35:12.458190Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::3
2023-01-24T06:35:12.458193Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.458195Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.458198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.458392Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035602,
    events_root: None,
}
2023-01-24T06:35:12.458402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-24T06:35:12.458404Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::8
2023-01-24T06:35:12.458406Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.458409Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.458410Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.458593Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124868,
    events_root: None,
}
2023-01-24T06:35:12.458602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-24T06:35:12.458605Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::13
2023-01-24T06:35:12.458607Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.458610Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.458611Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.458792Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124901,
    events_root: None,
}
2023-01-24T06:35:12.458802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-24T06:35:12.458805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::18
2023-01-24T06:35:12.458807Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.458809Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.458810Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.458990Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3124934,
    events_root: None,
}
2023-01-24T06:35:12.458999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:35:12.459002Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::4
2023-01-24T06:35:12.459004Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.459006Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.459007Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.459203Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4049395,
    events_root: None,
}
2023-01-24T06:35:12.459213Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-24T06:35:12.459216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::9
2023-01-24T06:35:12.459218Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.459221Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.459222Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.459412Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131149,
    events_root: None,
}
2023-01-24T06:35:12.459421Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-24T06:35:12.459423Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::14
2023-01-24T06:35:12.459426Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.459428Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.459430Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.459612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131182,
    events_root: None,
}
2023-01-24T06:35:12.459623Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-24T06:35:12.459625Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatasize"::Merge::19
2023-01-24T06:35:12.459627Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.459629Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T06:35:12.459631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.459824Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131215,
    events_root: None,
}
2023-01-24T06:35:12.461185Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/calldatasize.json"
2023-01-24T06:35:12.461213Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.487324Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:12.487429Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:12.487486Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487488Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:12.487546Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487548Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:12.487600Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487602Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:12.487649Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487651Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T06:35:12.487713Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487715Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T06:35:12.487771Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487773Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T06:35:12.487816Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487818Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T06:35:12.487862Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487864Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T06:35:12.487917Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487918Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-24T06:35:12.487965Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.487967Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-24T06:35:12.488015Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.488017Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-24T06:35:12.488059Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.488061Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-24T06:35:12.488105Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.488106Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-24T06:35:12.488162Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.488165Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-24T06:35:12.488215Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.488217Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-24T06:35:12.488260Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.488262Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-24T06:35:12.488314Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.488387Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:12.488392Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::0
2023-01-24T06:35:12.488395Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.488398Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.488399Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.844501Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.844523Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:12.844529Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::1
2023-01-24T06:35:12.844532Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.844535Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.844536Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.844862Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.844872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:12.844875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::2
2023-01-24T06:35:12.844877Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.844880Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.844881Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.845197Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.845208Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:35:12.845210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::3
2023-01-24T06:35:12.845212Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.845214Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.845216Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.845535Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.845545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:35:12.845548Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::4
2023-01-24T06:35:12.845550Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.845552Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.845554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.845859Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.845869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T06:35:12.845871Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::5
2023-01-24T06:35:12.845873Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.845876Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.845877Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.846181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.846191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T06:35:12.846193Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::6
2023-01-24T06:35:12.846195Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.846197Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.846199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.846503Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.846513Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T06:35:12.846516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::7
2023-01-24T06:35:12.846518Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.846520Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.846521Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.846826Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.846836Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-24T06:35:12.846838Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::8
2023-01-24T06:35:12.846840Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.846842Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.846844Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.847161Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.847173Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-24T06:35:12.847176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::9
2023-01-24T06:35:12.847179Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.847182Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.847183Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.847500Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.847512Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-24T06:35:12.847515Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::10
2023-01-24T06:35:12.847518Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.847521Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.847523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.847835Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.847848Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-24T06:35:12.847851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::11
2023-01-24T06:35:12.847854Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.847857Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.847859Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.848172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.848184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-24T06:35:12.848187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::12
2023-01-24T06:35:12.848190Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.848193Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.848195Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.848508Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.848520Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-24T06:35:12.848523Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::13
2023-01-24T06:35:12.848526Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.848529Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.848531Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.848849Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.848862Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-24T06:35:12.848867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::14
2023-01-24T06:35:12.848870Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.848873Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.848875Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.849192Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.849204Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-24T06:35:12.849208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Istanbul::15
2023-01-24T06:35:12.849211Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.849214Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.849216Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.849541Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648939,
    events_root: None,
}
2023-01-24T06:35:12.849554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:12.849558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::0
2023-01-24T06:35:12.849560Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.849563Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.849565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.849873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.849885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:12.849889Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::1
2023-01-24T06:35:12.849892Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.849895Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.849897Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.850198Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.850210Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:12.850214Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::2
2023-01-24T06:35:12.850217Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.850220Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.850222Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.850520Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.850532Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:35:12.850535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::3
2023-01-24T06:35:12.850538Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.850542Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.850544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.850842Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.850855Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:35:12.850860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::4
2023-01-24T06:35:12.850862Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.850865Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.850868Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.851166Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.851178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T06:35:12.851181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::5
2023-01-24T06:35:12.851184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.851187Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.851189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.851489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.851501Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T06:35:12.851504Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::6
2023-01-24T06:35:12.851507Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.851510Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.851512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.851811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.851823Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T06:35:12.851826Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::7
2023-01-24T06:35:12.851829Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.851832Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.851834Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.852139Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.852151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-24T06:35:12.852154Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::8
2023-01-24T06:35:12.852157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.852160Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.852162Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.852460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.852472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-24T06:35:12.852475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::9
2023-01-24T06:35:12.852478Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.852481Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.852483Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.852781Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.852794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-24T06:35:12.852797Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::10
2023-01-24T06:35:12.852800Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.852803Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.852805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.853107Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.853120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-24T06:35:12.853123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::11
2023-01-24T06:35:12.853125Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.853128Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.853131Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.853451Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.853463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-24T06:35:12.853466Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::12
2023-01-24T06:35:12.853468Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.853472Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.853473Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.853773Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.853785Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-24T06:35:12.853788Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::13
2023-01-24T06:35:12.853791Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.853794Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.853796Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.854090Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.854102Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-24T06:35:12.854106Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::14
2023-01-24T06:35:12.854108Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.854111Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.854114Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.854405Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.854417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-24T06:35:12.854421Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Berlin::15
2023-01-24T06:35:12.854423Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.854427Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.854429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.854722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.854734Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:12.854738Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::0
2023-01-24T06:35:12.854740Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.854743Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.854746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.855039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.855051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:12.855054Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::1
2023-01-24T06:35:12.855057Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.855061Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.855063Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.855355Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.855367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:12.855370Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::2
2023-01-24T06:35:12.855372Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.855376Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.855378Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.855671Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.855683Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:35:12.855686Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::3
2023-01-24T06:35:12.855689Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.855692Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.855694Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.855985Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.855997Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:35:12.856000Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::4
2023-01-24T06:35:12.856003Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.856006Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.856008Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.856300Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.856312Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T06:35:12.856315Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::5
2023-01-24T06:35:12.856318Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.856320Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.856323Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.856620Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.856632Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T06:35:12.856635Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::6
2023-01-24T06:35:12.856638Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.856641Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.856643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.856939Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.856951Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T06:35:12.856955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::7
2023-01-24T06:35:12.856957Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.856961Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.856962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.857268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.857281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-24T06:35:12.857284Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::8
2023-01-24T06:35:12.857287Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.857290Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.857292Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.857585Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.857597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-24T06:35:12.857600Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::9
2023-01-24T06:35:12.857602Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.857605Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.857609Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.857899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.857911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-24T06:35:12.857914Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::10
2023-01-24T06:35:12.857918Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.857921Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.857923Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.858221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.858233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-24T06:35:12.858236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::11
2023-01-24T06:35:12.858239Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.858242Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.858244Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.858535Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.858547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-24T06:35:12.858550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::12
2023-01-24T06:35:12.858553Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.858556Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.858558Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.858848Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.858860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-24T06:35:12.858863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::13
2023-01-24T06:35:12.858865Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.858868Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.858870Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.859160Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.859172Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-24T06:35:12.859175Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::14
2023-01-24T06:35:12.859179Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.859182Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.859184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.859475Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.859487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-24T06:35:12.859490Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::London::15
2023-01-24T06:35:12.859493Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.859497Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.859499Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.859789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.859801Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:12.859804Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::0
2023-01-24T06:35:12.859807Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.859810Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.859812Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.860103Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.860115Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:12.860118Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::1
2023-01-24T06:35:12.860121Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.860124Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.860126Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.860418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.860430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:12.860433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::2
2023-01-24T06:35:12.860436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.860439Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.860441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.860730Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.860742Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:35:12.860745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::3
2023-01-24T06:35:12.860748Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.860751Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.860753Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.861047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.861059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:35:12.861062Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::4
2023-01-24T06:35:12.861065Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.861068Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.861071Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.861371Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.861383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T06:35:12.861387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::5
2023-01-24T06:35:12.861389Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.861393Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.861395Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.861692Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.861704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T06:35:12.861707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::6
2023-01-24T06:35:12.861710Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.861713Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.861715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.862010Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.862022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T06:35:12.862025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::7
2023-01-24T06:35:12.862028Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.862031Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.862033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.862328Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.862340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-24T06:35:12.862345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::8
2023-01-24T06:35:12.862347Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.862350Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.862353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.862648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.862660Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-24T06:35:12.862665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::9
2023-01-24T06:35:12.862668Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.862671Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.862673Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.862967Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.862979Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-24T06:35:12.862982Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::10
2023-01-24T06:35:12.862984Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.862988Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.862989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.863284Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.863296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-24T06:35:12.863299Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::11
2023-01-24T06:35:12.863302Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.863305Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.863307Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.863605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.863617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-24T06:35:12.863620Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::12
2023-01-24T06:35:12.863623Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.863626Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.863628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.863924Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.863936Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-24T06:35:12.863939Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::13
2023-01-24T06:35:12.863942Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.863945Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.863947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.864241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.864253Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-24T06:35:12.864257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::14
2023-01-24T06:35:12.864259Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.864263Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.864265Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.864563Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.864575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-24T06:35:12.864578Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dup"::Merge::15
2023-01-24T06:35:12.864581Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.864584Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.864587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:12.864881Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841107,
    events_root: None,
}
2023-01-24T06:35:12.866204Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/dup.json"
2023-01-24T06:35:12.866231Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:12.890574Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:12.890680Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.890684Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:12.890737Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.890740Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:12.890798Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.890800Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:12.890854Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.890857Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:12.890905Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.890907Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T06:35:12.890970Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.890973Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T06:35:12.891029Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.891032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T06:35:12.891079Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.891082Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T06:35:12.891126Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.891129Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T06:35:12.891181Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.891184Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-24T06:35:12.891230Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.891233Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-24T06:35:12.891280Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:12.891351Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:12.891356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::0
2023-01-24T06:35:12.891360Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:12.891364Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:12.891366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.225316Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3989907,
    events_root: None,
}
2023-01-24T06:35:13.225344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:13.225352Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::1
2023-01-24T06:35:13.225355Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.225359Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.225361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.225564Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4039723,
    events_root: None,
}
2023-01-24T06:35:13.225579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:13.225583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::2
2023-01-24T06:35:13.225585Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.225589Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.225591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.225770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3070337,
    events_root: None,
}
2023-01-24T06:35:13.225781Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:35:13.225784Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::3
2023-01-24T06:35:13.225789Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.225793Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.225796Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.225975Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3072034,
    events_root: None,
}
2023-01-24T06:35:13.225986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:35:13.225989Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::4
2023-01-24T06:35:13.225991Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.225995Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.225997Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.226187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4015565,
    events_root: None,
}
2023-01-24T06:35:13.226201Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T06:35:13.226204Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::5
2023-01-24T06:35:13.226207Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.226210Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.226212Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.226401Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3991813,
    events_root: None,
}
2023-01-24T06:35:13.226414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T06:35:13.226418Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::6
2023-01-24T06:35:13.226420Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.226424Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.226426Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.226614Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3988168,
    events_root: None,
}
2023-01-24T06:35:13.226628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T06:35:13.226632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::7
2023-01-24T06:35:13.226634Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.226637Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.226639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.226835Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4010057,
    events_root: None,
}
2023-01-24T06:35:13.226849Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-24T06:35:13.226853Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::8
2023-01-24T06:35:13.226855Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.226859Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.226861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.227052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4030851,
    events_root: None,
}
2023-01-24T06:35:13.227066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-24T06:35:13.227069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Istanbul::9
2023-01-24T06:35:13.227072Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.227075Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.227077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.227251Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063373,
    events_root: None,
}
2023-01-24T06:35:13.227261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:13.227264Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::0
2023-01-24T06:35:13.227267Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.227271Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.227273Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.227453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3093029,
    events_root: None,
}
2023-01-24T06:35:13.227463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:13.227466Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::1
2023-01-24T06:35:13.227470Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.227474Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.227476Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.227652Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101037,
    events_root: None,
}
2023-01-24T06:35:13.227662Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:13.227665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::2
2023-01-24T06:35:13.227669Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.227673Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.227675Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.227855Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3070337,
    events_root: None,
}
2023-01-24T06:35:13.227865Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:35:13.227869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::3
2023-01-24T06:35:13.227872Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.227876Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.227878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.228052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3072034,
    events_root: None,
}
2023-01-24T06:35:13.228062Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:35:13.228065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::4
2023-01-24T06:35:13.228068Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.228071Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.228073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.228251Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3093635,
    events_root: None,
}
2023-01-24T06:35:13.228261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T06:35:13.228264Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::5
2023-01-24T06:35:13.228268Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.228272Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.228274Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.228451Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096226,
    events_root: None,
}
2023-01-24T06:35:13.228461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T06:35:13.228464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::6
2023-01-24T06:35:13.228468Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.228471Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.228473Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.228649Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3092582,
    events_root: None,
}
2023-01-24T06:35:13.228659Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T06:35:13.228663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::7
2023-01-24T06:35:13.228666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.228670Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.228672Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.228853Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3114470,
    events_root: None,
}
2023-01-24T06:35:13.228863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-24T06:35:13.228866Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::8
2023-01-24T06:35:13.228870Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.228874Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.228875Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.229052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3108921,
    events_root: None,
}
2023-01-24T06:35:13.229062Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-24T06:35:13.229066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Berlin::9
2023-01-24T06:35:13.229070Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.229073Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.229075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.229248Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063373,
    events_root: None,
}
2023-01-24T06:35:13.229282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:13.229286Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::0
2023-01-24T06:35:13.229288Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.229292Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.229295Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.229473Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3093029,
    events_root: None,
}
2023-01-24T06:35:13.229483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:13.229486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::1
2023-01-24T06:35:13.229490Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.229494Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.229496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.229675Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101037,
    events_root: None,
}
2023-01-24T06:35:13.229685Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:13.229689Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::2
2023-01-24T06:35:13.229692Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.229696Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.229698Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.229877Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3070337,
    events_root: None,
}
2023-01-24T06:35:13.229887Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:35:13.229890Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::3
2023-01-24T06:35:13.229893Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.229896Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.229898Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.230071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3072034,
    events_root: None,
}
2023-01-24T06:35:13.230081Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:35:13.230084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::4
2023-01-24T06:35:13.230087Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.230090Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.230092Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.230269Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3093635,
    events_root: None,
}
2023-01-24T06:35:13.230279Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T06:35:13.230283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::5
2023-01-24T06:35:13.230287Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.230290Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.230292Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.230468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096226,
    events_root: None,
}
2023-01-24T06:35:13.230478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T06:35:13.230481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::6
2023-01-24T06:35:13.230485Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.230489Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.230490Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.230664Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3092582,
    events_root: None,
}
2023-01-24T06:35:13.230675Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T06:35:13.230678Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::7
2023-01-24T06:35:13.230682Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.230685Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.230687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.230871Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3114470,
    events_root: None,
}
2023-01-24T06:35:13.230882Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-24T06:35:13.230885Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::8
2023-01-24T06:35:13.230888Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.230891Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.230894Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.231070Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3108921,
    events_root: None,
}
2023-01-24T06:35:13.231080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-24T06:35:13.231083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::London::9
2023-01-24T06:35:13.231087Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.231091Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.231093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.231265Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063373,
    events_root: None,
}
2023-01-24T06:35:13.231275Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:13.231278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::0
2023-01-24T06:35:13.231282Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.231286Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.231288Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.231464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3093029,
    events_root: None,
}
2023-01-24T06:35:13.231474Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:13.231478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::1
2023-01-24T06:35:13.231481Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.231485Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.231487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.231665Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101037,
    events_root: None,
}
2023-01-24T06:35:13.231675Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:13.231678Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::2
2023-01-24T06:35:13.231681Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.231684Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.231687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.231866Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3070337,
    events_root: None,
}
2023-01-24T06:35:13.231876Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:35:13.231879Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::3
2023-01-24T06:35:13.231883Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.231887Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.231889Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.232064Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3072034,
    events_root: None,
}
2023-01-24T06:35:13.232074Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:35:13.232077Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::4
2023-01-24T06:35:13.232081Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.232084Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.232086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.232264Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3093635,
    events_root: None,
}
2023-01-24T06:35:13.232274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T06:35:13.232277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::5
2023-01-24T06:35:13.232280Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.232283Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.232285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.232462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096226,
    events_root: None,
}
2023-01-24T06:35:13.232472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T06:35:13.232476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::6
2023-01-24T06:35:13.232479Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.232483Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.232485Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.232667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3092582,
    events_root: None,
}
2023-01-24T06:35:13.232677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T06:35:13.232681Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::7
2023-01-24T06:35:13.232685Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.232688Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.232690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.232872Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3114470,
    events_root: None,
}
2023-01-24T06:35:13.232882Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-24T06:35:13.232885Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::8
2023-01-24T06:35:13.232889Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.232893Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.232895Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.233074Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3108921,
    events_root: None,
}
2023-01-24T06:35:13.233084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-24T06:35:13.233088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "envInfo"::Merge::9
2023-01-24T06:35:13.233091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.233094Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.233096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.233280Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063373,
    events_root: None,
}
2023-01-24T06:35:13.234599Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/envInfo.json"
2023-01-24T06:35:13.234627Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.260077Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:13.260188Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260193Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:13.260247Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260249Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:13.260307Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260309Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:13.260363Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260366Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:13.260414Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260417Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T06:35:13.260479Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260482Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T06:35:13.260540Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260542Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T06:35:13.260588Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260591Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T06:35:13.260635Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260637Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T06:35:13.260691Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260693Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-24T06:35:13.260742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260744Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-24T06:35:13.260795Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260797Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-24T06:35:13.260840Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260843Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-24T06:35:13.260887Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260889Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-24T06:35:13.260946Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.260949Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-24T06:35:13.260999Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261002Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-24T06:35:13.261045Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261047Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-24T06:35:13.261094Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261097Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 18
2023-01-24T06:35:13.261150Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261153Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 19
2023-01-24T06:35:13.261188Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261191Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 20
2023-01-24T06:35:13.261236Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261238Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 21
2023-01-24T06:35:13.261307Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261309Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 22
2023-01-24T06:35:13.261377Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261379Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 23
2023-01-24T06:35:13.261436Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261438Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 24
2023-01-24T06:35:13.261490Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261492Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 25
2023-01-24T06:35:13.261562Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261564Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 26
2023-01-24T06:35:13.261611Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261613Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 27
2023-01-24T06:35:13.261663Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261665Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 28
2023-01-24T06:35:13.261723Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261727Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 29
2023-01-24T06:35:13.261785Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261787Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 30
2023-01-24T06:35:13.261829Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261832Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 31
2023-01-24T06:35:13.261891Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261894Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 32
2023-01-24T06:35:13.261953Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.261956Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 33
2023-01-24T06:35:13.262002Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.262076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:13.262082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::0
2023-01-24T06:35:13.262085Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.262089Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.262091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.626411Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3959613,
    events_root: None,
}
2023-01-24T06:35:13.626434Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:13.626442Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::1
2023-01-24T06:35:13.626445Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.626448Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.626450Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.626655Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3961014,
    events_root: None,
}
2023-01-24T06:35:13.626665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:13.626669Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::2
2023-01-24T06:35:13.626673Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.626676Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.626678Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.626889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3962387,
    events_root: None,
}
2023-01-24T06:35:13.626900Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:35:13.626903Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::3
2023-01-24T06:35:13.626907Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.626910Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.626912Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.627111Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3963761,
    events_root: None,
}
2023-01-24T06:35:13.627123Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:35:13.627126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::4
2023-01-24T06:35:13.627128Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.627130Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.627132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.627323Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3965134,
    events_root: None,
}
2023-01-24T06:35:13.627332Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T06:35:13.627335Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::5
2023-01-24T06:35:13.627336Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.627339Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.627340Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.627527Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3968715,
    events_root: None,
}
2023-01-24T06:35:13.627537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T06:35:13.627540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::6
2023-01-24T06:35:13.627542Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.627544Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.627546Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.627734Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3970088,
    events_root: None,
}
2023-01-24T06:35:13.627742Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T06:35:13.627745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::7
2023-01-24T06:35:13.627747Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.627750Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.627751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.627938Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3971461,
    events_root: None,
}
2023-01-24T06:35:13.627947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-24T06:35:13.627949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::8
2023-01-24T06:35:13.627951Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.627953Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.627954Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.628140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3972851,
    events_root: None,
}
2023-01-24T06:35:13.628150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-24T06:35:13.628153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::9
2023-01-24T06:35:13.628155Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.628157Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.628159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.628345Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3974244,
    events_root: None,
}
2023-01-24T06:35:13.628354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-24T06:35:13.628357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::10
2023-01-24T06:35:13.628359Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.628361Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.628363Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.628552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3975629,
    events_root: None,
}
2023-01-24T06:35:13.628562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-24T06:35:13.628564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::11
2023-01-24T06:35:13.628567Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.628569Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.628571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.628756Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3976626,
    events_root: None,
}
2023-01-24T06:35:13.628766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-24T06:35:13.628769Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::12
2023-01-24T06:35:13.628771Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.628773Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.628775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.628961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3978035,
    events_root: None,
}
2023-01-24T06:35:13.628970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-24T06:35:13.628972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::13
2023-01-24T06:35:13.628974Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.628977Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.628978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.629164Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3979441,
    events_root: None,
}
2023-01-24T06:35:13.629173Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-24T06:35:13.629176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::14
2023-01-24T06:35:13.629178Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.629180Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.629181Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.629375Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3980846,
    events_root: None,
}
2023-01-24T06:35:13.629385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-24T06:35:13.629388Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::15
2023-01-24T06:35:13.629390Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.629392Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.629393Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.629579Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3980708,
    events_root: None,
}
2023-01-24T06:35:13.629588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 16
2023-01-24T06:35:13.629591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::16
2023-01-24T06:35:13.629593Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.629595Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.629596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.629781Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3983384,
    events_root: None,
}
2023-01-24T06:35:13.629791Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 17
2023-01-24T06:35:13.629793Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::17
2023-01-24T06:35:13.629795Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.629798Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.629800Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.629987Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3984777,
    events_root: None,
}
2023-01-24T06:35:13.629996Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 18
2023-01-24T06:35:13.629998Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::18
2023-01-24T06:35:13.630001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.630003Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.630004Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.630191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3986163,
    events_root: None,
}
2023-01-24T06:35:13.630200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 19
2023-01-24T06:35:13.630202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::19
2023-01-24T06:35:13.630204Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.630207Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.630208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.630394Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3987388,
    events_root: None,
}
2023-01-24T06:35:13.630403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 20
2023-01-24T06:35:13.630405Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::20
2023-01-24T06:35:13.630408Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.630411Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.630412Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.630598Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3988797,
    events_root: None,
}
2023-01-24T06:35:13.630607Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 21
2023-01-24T06:35:13.630609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::21
2023-01-24T06:35:13.630611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.630614Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.630615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.630801Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3990202,
    events_root: None,
}
2023-01-24T06:35:13.630810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 22
2023-01-24T06:35:13.630812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::22
2023-01-24T06:35:13.630815Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.630817Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.630819Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.631004Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3991607,
    events_root: None,
}
2023-01-24T06:35:13.631013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 23
2023-01-24T06:35:13.631016Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::23
2023-01-24T06:35:13.631018Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.631021Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.631022Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.631209Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3994123,
    events_root: None,
}
2023-01-24T06:35:13.631219Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 24
2023-01-24T06:35:13.631222Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::24
2023-01-24T06:35:13.631224Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.631226Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.631228Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.631413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3995504,
    events_root: None,
}
2023-01-24T06:35:13.631422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 25
2023-01-24T06:35:13.631424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::25
2023-01-24T06:35:13.631427Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.631430Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.631431Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.631625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3996897,
    events_root: None,
}
2023-01-24T06:35:13.631635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 26
2023-01-24T06:35:13.631637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::26
2023-01-24T06:35:13.631639Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.631642Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.631643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.631828Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3998283,
    events_root: None,
}
2023-01-24T06:35:13.631837Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 27
2023-01-24T06:35:13.631840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::27
2023-01-24T06:35:13.631842Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.631844Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.631846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.632030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3999508,
    events_root: None,
}
2023-01-24T06:35:13.632039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 28
2023-01-24T06:35:13.632042Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::28
2023-01-24T06:35:13.632044Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.632047Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.632048Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.632234Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000917,
    events_root: None,
}
2023-01-24T06:35:13.632243Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 29
2023-01-24T06:35:13.632246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::29
2023-01-24T06:35:13.632248Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.632250Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.632252Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.632437Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4002322,
    events_root: None,
}
2023-01-24T06:35:13.632447Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 30
2023-01-24T06:35:13.632449Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::30
2023-01-24T06:35:13.632451Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.632453Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.632455Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.632639Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003727,
    events_root: None,
}
2023-01-24T06:35:13.632648Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 31
2023-01-24T06:35:13.632651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Istanbul::31
2023-01-24T06:35:13.632653Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.632656Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.632657Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.632842Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003590,
    events_root: None,
}
2023-01-24T06:35:13.632853Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:13.632855Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::0
2023-01-24T06:35:13.632857Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.632860Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.632861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.633036Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064027,
    events_root: None,
}
2023-01-24T06:35:13.633045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:13.633048Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::1
2023-01-24T06:35:13.633050Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.633052Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.633053Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.633225Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064136,
    events_root: None,
}
2023-01-24T06:35:13.633234Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:13.633237Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::2
2023-01-24T06:35:13.633239Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.633241Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.633242Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.633421Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064217,
    events_root: None,
}
2023-01-24T06:35:13.633430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:35:13.633433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::3
2023-01-24T06:35:13.633435Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.633437Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.633439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.633610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064298,
    events_root: None,
}
2023-01-24T06:35:13.633618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:35:13.633621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::4
2023-01-24T06:35:13.633623Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.633625Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.633627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.633798Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064379,
    events_root: None,
}
2023-01-24T06:35:13.633807Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T06:35:13.633810Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::5
2023-01-24T06:35:13.633812Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.633814Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.633816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.633986Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064461,
    events_root: None,
}
2023-01-24T06:35:13.633995Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T06:35:13.633997Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::6
2023-01-24T06:35:13.633999Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.634001Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.634003Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.634174Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064542,
    events_root: None,
}
2023-01-24T06:35:13.634183Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T06:35:13.634185Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::7
2023-01-24T06:35:13.634187Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.634190Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.634192Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.634384Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064623,
    events_root: None,
}
2023-01-24T06:35:13.634396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-24T06:35:13.634399Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::8
2023-01-24T06:35:13.634402Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.634404Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.634406Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.634628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064720,
    events_root: None,
}
2023-01-24T06:35:13.634637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-24T06:35:13.634640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::9
2023-01-24T06:35:13.634642Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.634644Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.634646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.634821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064821,
    events_root: None,
}
2023-01-24T06:35:13.634830Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-24T06:35:13.634833Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::10
2023-01-24T06:35:13.634835Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.634838Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.634839Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.635068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064915,
    events_root: None,
}
2023-01-24T06:35:13.635079Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-24T06:35:13.635083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::11
2023-01-24T06:35:13.635085Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.635088Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.635090Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.635314Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064620,
    events_root: None,
}
2023-01-24T06:35:13.635324Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-24T06:35:13.635326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::12
2023-01-24T06:35:13.635328Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.635331Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.635332Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.635535Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064737,
    events_root: None,
}
2023-01-24T06:35:13.635544Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-24T06:35:13.635547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::13
2023-01-24T06:35:13.635549Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.635551Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.635553Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.635781Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064850,
    events_root: None,
}
2023-01-24T06:35:13.635792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-24T06:35:13.635795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::14
2023-01-24T06:35:13.635797Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.635800Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.635802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.636033Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064963,
    events_root: None,
}
2023-01-24T06:35:13.636044Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-24T06:35:13.636048Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::15
2023-01-24T06:35:13.636050Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.636054Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.636056Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.636297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064826,
    events_root: None,
}
2023-01-24T06:35:13.636307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-24T06:35:13.636309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::16
2023-01-24T06:35:13.636311Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.636314Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.636315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.636526Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064918,
    events_root: None,
}
2023-01-24T06:35:13.636537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-24T06:35:13.636541Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::17
2023-01-24T06:35:13.636543Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.636546Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.636548Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.636773Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065019,
    events_root: None,
}
2023-01-24T06:35:13.636784Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-24T06:35:13.636787Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::18
2023-01-24T06:35:13.636790Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.636793Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.636794Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.637026Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065112,
    events_root: None,
}
2023-01-24T06:35:13.637038Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-24T06:35:13.637041Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::19
2023-01-24T06:35:13.637043Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.637047Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.637049Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.637268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065045,
    events_root: None,
}
2023-01-24T06:35:13.637277Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 20
2023-01-24T06:35:13.637280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::20
2023-01-24T06:35:13.637282Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.637285Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.637286Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.637460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065163,
    events_root: None,
}
2023-01-24T06:35:13.637469Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 21
2023-01-24T06:35:13.637472Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::21
2023-01-24T06:35:13.637474Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.637476Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.637477Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.637648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065276,
    events_root: None,
}
2023-01-24T06:35:13.637657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 22
2023-01-24T06:35:13.637659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::22
2023-01-24T06:35:13.637661Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.637664Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.637665Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.637835Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065389,
    events_root: None,
}
2023-01-24T06:35:13.637844Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 23
2023-01-24T06:35:13.637846Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::23
2023-01-24T06:35:13.637848Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.637851Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.637852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.638023Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065361,
    events_root: None,
}
2023-01-24T06:35:13.638032Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 24
2023-01-24T06:35:13.638035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::24
2023-01-24T06:35:13.638037Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.638041Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.638042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.638212Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065450,
    events_root: None,
}
2023-01-24T06:35:13.638221Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 25
2023-01-24T06:35:13.638224Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::25
2023-01-24T06:35:13.638226Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.638228Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.638230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.638399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065551,
    events_root: None,
}
2023-01-24T06:35:13.638409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 26
2023-01-24T06:35:13.638412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::26
2023-01-24T06:35:13.638413Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.638415Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.638417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.638588Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065644,
    events_root: None,
}
2023-01-24T06:35:13.638597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 27
2023-01-24T06:35:13.638599Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::27
2023-01-24T06:35:13.638601Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.638603Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.638605Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.638775Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065577,
    events_root: None,
}
2023-01-24T06:35:13.638784Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 28
2023-01-24T06:35:13.638787Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::28
2023-01-24T06:35:13.638789Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.638791Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.638793Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.638963Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065695,
    events_root: None,
}
2023-01-24T06:35:13.638971Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 29
2023-01-24T06:35:13.638974Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::29
2023-01-24T06:35:13.638976Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.638978Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.638980Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.639150Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065808,
    events_root: None,
}
2023-01-24T06:35:13.639159Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 30
2023-01-24T06:35:13.639161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::30
2023-01-24T06:35:13.639163Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.639165Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.639167Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.639337Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065921,
    events_root: None,
}
2023-01-24T06:35:13.639345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 31
2023-01-24T06:35:13.639348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Berlin::31
2023-01-24T06:35:13.639350Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.639352Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.639353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.639524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065783,
    events_root: None,
}
2023-01-24T06:35:13.639532Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:13.639535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::0
2023-01-24T06:35:13.639537Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.639540Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.639541Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.639712Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064027,
    events_root: None,
}
2023-01-24T06:35:13.639720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:13.639723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::1
2023-01-24T06:35:13.639725Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.639727Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.639729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.639899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064136,
    events_root: None,
}
2023-01-24T06:35:13.639908Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:13.639911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::2
2023-01-24T06:35:13.639913Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.639915Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.639917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.640087Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064217,
    events_root: None,
}
2023-01-24T06:35:13.640096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:35:13.640098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::3
2023-01-24T06:35:13.640100Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.640103Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.640104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.640273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064298,
    events_root: None,
}
2023-01-24T06:35:13.640282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:35:13.640285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::4
2023-01-24T06:35:13.640286Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.640289Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.640290Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.640460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064379,
    events_root: None,
}
2023-01-24T06:35:13.640468Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T06:35:13.640471Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::5
2023-01-24T06:35:13.640473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.640475Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.640477Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.640647Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064461,
    events_root: None,
}
2023-01-24T06:35:13.640655Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T06:35:13.640658Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::6
2023-01-24T06:35:13.640660Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.640663Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.640664Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.640836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064542,
    events_root: None,
}
2023-01-24T06:35:13.640845Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T06:35:13.640848Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::7
2023-01-24T06:35:13.640850Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.640852Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.640854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.641025Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064623,
    events_root: None,
}
2023-01-24T06:35:13.641034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-24T06:35:13.641037Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::8
2023-01-24T06:35:13.641039Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.641041Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.641043Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.641213Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064720,
    events_root: None,
}
2023-01-24T06:35:13.641222Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-24T06:35:13.641224Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::9
2023-01-24T06:35:13.641226Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.641229Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.641230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.641407Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064821,
    events_root: None,
}
2023-01-24T06:35:13.641416Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-24T06:35:13.641419Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::10
2023-01-24T06:35:13.641421Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.641423Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.641424Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.641600Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064915,
    events_root: None,
}
2023-01-24T06:35:13.641609Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-24T06:35:13.641611Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::11
2023-01-24T06:35:13.641613Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.641615Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.641616Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.641788Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064620,
    events_root: None,
}
2023-01-24T06:35:13.641796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-24T06:35:13.641799Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::12
2023-01-24T06:35:13.641801Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.641803Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.641805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.641974Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064737,
    events_root: None,
}
2023-01-24T06:35:13.641983Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-24T06:35:13.641985Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::13
2023-01-24T06:35:13.641987Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.641989Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.641991Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.642160Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064850,
    events_root: None,
}
2023-01-24T06:35:13.642169Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-24T06:35:13.642171Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::14
2023-01-24T06:35:13.642173Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.642176Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.642177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.642346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064963,
    events_root: None,
}
2023-01-24T06:35:13.642355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-24T06:35:13.642357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::15
2023-01-24T06:35:13.642360Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.642362Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.642364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.642539Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064826,
    events_root: None,
}
2023-01-24T06:35:13.642548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-24T06:35:13.642550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::16
2023-01-24T06:35:13.642553Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.642556Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.642557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.642727Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064918,
    events_root: None,
}
2023-01-24T06:35:13.642736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-24T06:35:13.642739Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::17
2023-01-24T06:35:13.642741Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.642744Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.642745Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.642914Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065019,
    events_root: None,
}
2023-01-24T06:35:13.642924Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-24T06:35:13.642926Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::18
2023-01-24T06:35:13.642928Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.642931Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.642932Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.643102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065112,
    events_root: None,
}
2023-01-24T06:35:13.643111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-24T06:35:13.643114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::19
2023-01-24T06:35:13.643116Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.643118Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.643119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.643290Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065045,
    events_root: None,
}
2023-01-24T06:35:13.643299Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-24T06:35:13.643301Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::20
2023-01-24T06:35:13.643303Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.643306Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.643307Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.643479Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065163,
    events_root: None,
}
2023-01-24T06:35:13.643487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-24T06:35:13.643490Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::21
2023-01-24T06:35:13.643492Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.643494Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.643496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.643667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065276,
    events_root: None,
}
2023-01-24T06:35:13.643675Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-24T06:35:13.643678Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::22
2023-01-24T06:35:13.643680Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.643682Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.643684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.643855Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065389,
    events_root: None,
}
2023-01-24T06:35:13.643863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-24T06:35:13.643866Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::23
2023-01-24T06:35:13.643868Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.643870Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.643872Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.644042Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065361,
    events_root: None,
}
2023-01-24T06:35:13.644051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 24
2023-01-24T06:35:13.644054Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::24
2023-01-24T06:35:13.644056Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.644058Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.644060Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.644231Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065450,
    events_root: None,
}
2023-01-24T06:35:13.644239Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 25
2023-01-24T06:35:13.644242Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::25
2023-01-24T06:35:13.644244Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.644246Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.644248Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.644418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065551,
    events_root: None,
}
2023-01-24T06:35:13.644427Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 26
2023-01-24T06:35:13.644429Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::26
2023-01-24T06:35:13.644431Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.644434Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.644436Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.644606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065644,
    events_root: None,
}
2023-01-24T06:35:13.644616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 27
2023-01-24T06:35:13.644618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::27
2023-01-24T06:35:13.644620Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.644622Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.644624Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.644794Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065577,
    events_root: None,
}
2023-01-24T06:35:13.644803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 28
2023-01-24T06:35:13.644805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::28
2023-01-24T06:35:13.644807Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.644809Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.644811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.644982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065695,
    events_root: None,
}
2023-01-24T06:35:13.644991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 29
2023-01-24T06:35:13.644993Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::29
2023-01-24T06:35:13.644996Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.644998Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.645000Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.645169Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065808,
    events_root: None,
}
2023-01-24T06:35:13.645178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 30
2023-01-24T06:35:13.645181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::30
2023-01-24T06:35:13.645183Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.645186Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.645187Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.645364Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065921,
    events_root: None,
}
2023-01-24T06:35:13.645373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 31
2023-01-24T06:35:13.645376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::London::31
2023-01-24T06:35:13.645378Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.645380Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.645381Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.645553Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065783,
    events_root: None,
}
2023-01-24T06:35:13.645561Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:13.645564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::0
2023-01-24T06:35:13.645566Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.645568Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.645570Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.645740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064027,
    events_root: None,
}
2023-01-24T06:35:13.645749Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:13.645752Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::1
2023-01-24T06:35:13.645753Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.645756Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.645757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.645927Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064136,
    events_root: None,
}
2023-01-24T06:35:13.645936Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:13.645939Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::2
2023-01-24T06:35:13.645940Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.645943Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.645944Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.646114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064217,
    events_root: None,
}
2023-01-24T06:35:13.646122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:35:13.646125Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::3
2023-01-24T06:35:13.646127Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.646129Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.646131Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.646299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064298,
    events_root: None,
}
2023-01-24T06:35:13.646308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:35:13.646311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::4
2023-01-24T06:35:13.646312Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.646315Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.646316Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.646487Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064379,
    events_root: None,
}
2023-01-24T06:35:13.646496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T06:35:13.646498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::5
2023-01-24T06:35:13.646500Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.646502Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.646504Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.646673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064461,
    events_root: None,
}
2023-01-24T06:35:13.646682Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T06:35:13.646684Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::6
2023-01-24T06:35:13.646686Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.646689Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.646690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.646861Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064542,
    events_root: None,
}
2023-01-24T06:35:13.646869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T06:35:13.646872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::7
2023-01-24T06:35:13.646874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.646877Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.646878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.647049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064623,
    events_root: None,
}
2023-01-24T06:35:13.647058Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-24T06:35:13.647061Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::8
2023-01-24T06:35:13.647063Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.647065Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.647066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.647237Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064720,
    events_root: None,
}
2023-01-24T06:35:13.647246Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-24T06:35:13.647248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::9
2023-01-24T06:35:13.647250Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.647253Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.647255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.647426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064821,
    events_root: None,
}
2023-01-24T06:35:13.647435Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-24T06:35:13.647438Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::10
2023-01-24T06:35:13.647440Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.647442Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.647444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.647616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064915,
    events_root: None,
}
2023-01-24T06:35:13.647625Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-24T06:35:13.647628Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::11
2023-01-24T06:35:13.647630Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.647632Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.647633Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.647803Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064620,
    events_root: None,
}
2023-01-24T06:35:13.647812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-24T06:35:13.647815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::12
2023-01-24T06:35:13.647817Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.647819Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.647820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.647990Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064737,
    events_root: None,
}
2023-01-24T06:35:13.647999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-24T06:35:13.648001Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::13
2023-01-24T06:35:13.648003Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.648006Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.648007Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.648177Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064850,
    events_root: None,
}
2023-01-24T06:35:13.648186Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-24T06:35:13.648189Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::14
2023-01-24T06:35:13.648191Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.648193Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.648194Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.648365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064963,
    events_root: None,
}
2023-01-24T06:35:13.648374Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-24T06:35:13.648376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::15
2023-01-24T06:35:13.648378Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.648380Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.648382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.648578Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064826,
    events_root: None,
}
2023-01-24T06:35:13.648589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-24T06:35:13.648593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::16
2023-01-24T06:35:13.648595Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.648598Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.648600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.648773Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064918,
    events_root: None,
}
2023-01-24T06:35:13.648783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-24T06:35:13.648786Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::17
2023-01-24T06:35:13.648788Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.648790Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.648791Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.648961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065019,
    events_root: None,
}
2023-01-24T06:35:13.648970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-24T06:35:13.648973Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::18
2023-01-24T06:35:13.648975Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.648977Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.648979Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.649149Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065112,
    events_root: None,
}
2023-01-24T06:35:13.649158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-24T06:35:13.649161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::19
2023-01-24T06:35:13.649163Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.649165Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.649166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.649353Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065045,
    events_root: None,
}
2023-01-24T06:35:13.649363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-24T06:35:13.649366Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::20
2023-01-24T06:35:13.649369Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.649371Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.649373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.649559Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065163,
    events_root: None,
}
2023-01-24T06:35:13.649567Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-24T06:35:13.649570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::21
2023-01-24T06:35:13.649571Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.649575Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.649576Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.649746Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065276,
    events_root: None,
}
2023-01-24T06:35:13.649755Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-24T06:35:13.649758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::22
2023-01-24T06:35:13.649760Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.649763Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.649764Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.649935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065389,
    events_root: None,
}
2023-01-24T06:35:13.649944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-24T06:35:13.649947Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::23
2023-01-24T06:35:13.649949Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.649951Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.649953Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.650124Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065361,
    events_root: None,
}
2023-01-24T06:35:13.650133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-24T06:35:13.650136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::24
2023-01-24T06:35:13.650138Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.650140Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.650141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.650313Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065450,
    events_root: None,
}
2023-01-24T06:35:13.650322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-24T06:35:13.650325Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::25
2023-01-24T06:35:13.650327Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.650330Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.650331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.650501Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065551,
    events_root: None,
}
2023-01-24T06:35:13.650510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-24T06:35:13.650512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::26
2023-01-24T06:35:13.650514Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.650517Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.650518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.650690Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065644,
    events_root: None,
}
2023-01-24T06:35:13.650699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-24T06:35:13.650702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::27
2023-01-24T06:35:13.650703Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.650706Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.650707Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.650877Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065577,
    events_root: None,
}
2023-01-24T06:35:13.650886Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-24T06:35:13.650888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::28
2023-01-24T06:35:13.650890Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.650893Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.650894Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.651064Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065695,
    events_root: None,
}
2023-01-24T06:35:13.651073Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-24T06:35:13.651076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::29
2023-01-24T06:35:13.651078Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.651080Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.651081Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.651251Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065808,
    events_root: None,
}
2023-01-24T06:35:13.651260Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-24T06:35:13.651262Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::30
2023-01-24T06:35:13.651264Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.651266Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.651268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.651466Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065921,
    events_root: None,
}
2023-01-24T06:35:13.651476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-24T06:35:13.651478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push"::Merge::31
2023-01-24T06:35:13.651480Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.651482Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.651484Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:13.651667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065783,
    events_root: None,
}
2023-01-24T06:35:13.653543Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/push.json"
2023-01-24T06:35:13.653571Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:13.679644Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:13.679749Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.679752Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:13.679803Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.679805Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:13.679861Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.679863Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:13.679914Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.679916Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:13.679961Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.679964Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T06:35:13.680029Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.680032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T06:35:13.680092Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.680094Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T06:35:13.680142Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:13.680224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:13.680229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Istanbul::0
2023-01-24T06:35:13.680233Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:13.680237Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:13.680239Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.015762Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3109598,
    events_root: None,
}
2023-01-24T06:35:14.015783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:14.015789Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Istanbul::1
2023-01-24T06:35:14.015791Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.015794Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.015795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.015986Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053393,
    events_root: None,
}
2023-01-24T06:35:14.015995Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:14.015997Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Istanbul::2
2023-01-24T06:35:14.015999Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.016002Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.016003Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.016178Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053292,
    events_root: None,
}
2023-01-24T06:35:14.016187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:35:14.016189Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Istanbul::3
2023-01-24T06:35:14.016191Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.016193Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.016195Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.016368Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032388,
    events_root: None,
}
2023-01-24T06:35:14.016377Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:35:14.016379Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Istanbul::4
2023-01-24T06:35:14.016381Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.016383Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.016385Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.016554Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031466,
    events_root: None,
}
2023-01-24T06:35:14.016562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T06:35:14.016565Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Istanbul::5
2023-01-24T06:35:14.016567Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.016569Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.016571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.016743Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3051485,
    events_root: None,
}
2023-01-24T06:35:14.016751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:14.016754Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Berlin::0
2023-01-24T06:35:14.016756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.016758Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.016760Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.016934Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3109598,
    events_root: None,
}
2023-01-24T06:35:14.016942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:14.016945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Berlin::1
2023-01-24T06:35:14.016947Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.016949Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.016951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.017123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053393,
    events_root: None,
}
2023-01-24T06:35:14.017133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:14.017136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Berlin::2
2023-01-24T06:35:14.017138Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.017142Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.017144Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.017340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053292,
    events_root: None,
}
2023-01-24T06:35:14.017350Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:35:14.017353Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Berlin::3
2023-01-24T06:35:14.017356Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.017359Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.017361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.017538Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032388,
    events_root: None,
}
2023-01-24T06:35:14.017548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:35:14.017551Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Berlin::4
2023-01-24T06:35:14.017553Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.017557Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.017559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.017730Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031466,
    events_root: None,
}
2023-01-24T06:35:14.017740Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T06:35:14.017743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Berlin::5
2023-01-24T06:35:14.017747Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.017751Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.017752Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.017929Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3051485,
    events_root: None,
}
2023-01-24T06:35:14.017939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:14.017943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::London::0
2023-01-24T06:35:14.017945Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.017949Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.017951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.018133Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3109598,
    events_root: None,
}
2023-01-24T06:35:14.018143Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:14.018146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::London::1
2023-01-24T06:35:14.018150Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.018154Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.018156Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.018339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053393,
    events_root: None,
}
2023-01-24T06:35:14.018349Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:14.018352Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::London::2
2023-01-24T06:35:14.018354Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.018358Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.018360Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.018541Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053292,
    events_root: None,
}
2023-01-24T06:35:14.018550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:35:14.018554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::London::3
2023-01-24T06:35:14.018556Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.018560Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.018562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.018735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032388,
    events_root: None,
}
2023-01-24T06:35:14.018745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:35:14.018748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::London::4
2023-01-24T06:35:14.018752Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.018756Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.018758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.018929Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031466,
    events_root: None,
}
2023-01-24T06:35:14.018938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T06:35:14.018942Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::London::5
2023-01-24T06:35:14.018946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.018949Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.018951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.019127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3051485,
    events_root: None,
}
2023-01-24T06:35:14.019137Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:14.019141Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Merge::0
2023-01-24T06:35:14.019145Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.019148Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.019150Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.019338Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3109598,
    events_root: None,
}
2023-01-24T06:35:14.019348Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:14.019351Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Merge::1
2023-01-24T06:35:14.019355Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.019359Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.019361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.019571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053393,
    events_root: None,
}
2023-01-24T06:35:14.019582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:14.019585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Merge::2
2023-01-24T06:35:14.019587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.019590Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.019602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.019841Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3053292,
    events_root: None,
}
2023-01-24T06:35:14.019851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:35:14.019854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Merge::3
2023-01-24T06:35:14.019857Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.019860Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.019862Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.020047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032388,
    events_root: None,
}
2023-01-24T06:35:14.020057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:35:14.020060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Merge::4
2023-01-24T06:35:14.020063Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.020066Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.020068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.020252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031466,
    events_root: None,
}
2023-01-24T06:35:14.020262Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T06:35:14.020266Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "random"::Merge::5
2023-01-24T06:35:14.020268Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.020272Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.020273Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.020452Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3051485,
    events_root: None,
}
2023-01-24T06:35:14.021760Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/random.json"
2023-01-24T06:35:14.021786Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.046821Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:14.046923Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.046926Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:14.046979Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.046981Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:14.047037Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047039Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:14.047090Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047092Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:14.047140Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047142Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T06:35:14.047203Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047205Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T06:35:14.047259Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047261Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T06:35:14.047304Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047306Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T06:35:14.047348Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047350Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T06:35:14.047401Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047403Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-24T06:35:14.047450Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047452Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-24T06:35:14.047498Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047499Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-24T06:35:14.047541Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047542Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-24T06:35:14.047585Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047587Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-24T06:35:14.047642Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047645Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-24T06:35:14.047693Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047695Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-24T06:35:14.047736Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047739Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-24T06:35:14.047792Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047794Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 18
2023-01-24T06:35:14.047851Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.047925Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:14.047931Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::0
2023-01-24T06:35:14.047935Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.047938Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.047940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.409445Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4068450,
    events_root: None,
}
2023-01-24T06:35:14.409469Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:14.409477Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::1
2023-01-24T06:35:14.409480Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.409484Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.409485Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.409692Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4069256,
    events_root: None,
}
2023-01-24T06:35:14.409704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:14.409707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::2
2023-01-24T06:35:14.409710Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.409713Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.409716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.409911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4069421,
    events_root: None,
}
2023-01-24T06:35:14.409922Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:35:14.409925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::3
2023-01-24T06:35:14.409927Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.409931Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.409933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.413075Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 39613873,
    events_root: None,
}
2023-01-24T06:35:14.413086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:35:14.413089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::4
2023-01-24T06:35:14.413091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.413095Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.413097Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.413314Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103077,
    events_root: None,
}
2023-01-24T06:35:14.413324Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T06:35:14.413328Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::5
2023-01-24T06:35:14.413330Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.413334Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.413335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.413521Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103099,
    events_root: None,
}
2023-01-24T06:35:14.413532Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T06:35:14.413535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::6
2023-01-24T06:35:14.413539Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.413542Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.413544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.413729Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3104836,
    events_root: None,
}
2023-01-24T06:35:14.413739Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T06:35:14.413742Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::7
2023-01-24T06:35:14.413746Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.413749Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.413751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.413933Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103606,
    events_root: None,
}
2023-01-24T06:35:14.413943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-24T06:35:14.413946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::8
2023-01-24T06:35:14.413949Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.413952Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.413954Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.418166Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17594951,
    events_root: None,
}
2023-01-24T06:35:14.418200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-24T06:35:14.418210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::9
2023-01-24T06:35:14.418213Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.418217Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.418221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.418542Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4069606,
    events_root: None,
}
2023-01-24T06:35:14.418553Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-24T06:35:14.418557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::10
2023-01-24T06:35:14.418560Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.418564Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.418566Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.418769Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4069619,
    events_root: None,
}
2023-01-24T06:35:14.418784Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-24T06:35:14.418787Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::11
2023-01-24T06:35:14.418790Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.418793Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.418795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.418988Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4069632,
    events_root: None,
}
2023-01-24T06:35:14.419002Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-24T06:35:14.419006Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::12
2023-01-24T06:35:14.419008Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.419011Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.419014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.419214Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4070016,
    events_root: None,
}
2023-01-24T06:35:14.419229Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-24T06:35:14.419232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::13
2023-01-24T06:35:14.419235Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.419238Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.419240Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.419433Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4070029,
    events_root: None,
}
2023-01-24T06:35:14.419447Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-24T06:35:14.419451Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::15
2023-01-24T06:35:14.419453Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.419457Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.419459Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.419650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4070042,
    events_root: None,
}
2023-01-24T06:35:14.419665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 16
2023-01-24T06:35:14.419668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::16
2023-01-24T06:35:14.419671Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.419674Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.419676Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.419876Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4068549,
    events_root: None,
}
2023-01-24T06:35:14.419890Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-24T06:35:14.419893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Istanbul::14
2023-01-24T06:35:14.419896Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.419900Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.419902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.420096Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4071028,
    events_root: None,
}
2023-01-24T06:35:14.420111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:14.420114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::0
2023-01-24T06:35:14.420117Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.420120Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.420122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.420308Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3129708,
    events_root: None,
}
2023-01-24T06:35:14.420321Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:14.420326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::1
2023-01-24T06:35:14.420328Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.420332Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.420334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.420511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130514,
    events_root: None,
}
2023-01-24T06:35:14.420524Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:14.420527Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::2
2023-01-24T06:35:14.420529Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.420533Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.420535Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.420717Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130679,
    events_root: None,
}
2023-01-24T06:35:14.420730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:35:14.420733Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::3
2023-01-24T06:35:14.420736Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.420739Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.420741Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.423834Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 38668279,
    events_root: None,
}
2023-01-24T06:35:14.423848Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:35:14.423851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::4
2023-01-24T06:35:14.423854Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.423857Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.423859Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.424056Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103077,
    events_root: None,
}
2023-01-24T06:35:14.424066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T06:35:14.424069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::5
2023-01-24T06:35:14.424073Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.424077Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.424078Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.424259Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103099,
    events_root: None,
}
2023-01-24T06:35:14.424269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T06:35:14.424273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::6
2023-01-24T06:35:14.424276Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.424280Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.424282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.424464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3104836,
    events_root: None,
}
2023-01-24T06:35:14.424474Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T06:35:14.424477Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::7
2023-01-24T06:35:14.424480Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.424483Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.424485Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.424672Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103606,
    events_root: None,
}
2023-01-24T06:35:14.424683Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-24T06:35:14.424686Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::8
2023-01-24T06:35:14.424690Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.424693Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.424695Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.428800Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16649357,
    events_root: None,
}
2023-01-24T06:35:14.428829Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-24T06:35:14.428837Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::9
2023-01-24T06:35:14.428840Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.428844Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.428846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.429125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130864,
    events_root: None,
}
2023-01-24T06:35:14.429138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-24T06:35:14.429142Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::10
2023-01-24T06:35:14.429144Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.429147Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.429149Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.429341Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130877,
    events_root: None,
}
2023-01-24T06:35:14.429355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-24T06:35:14.429358Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::11
2023-01-24T06:35:14.429361Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.429364Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.429366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.429546Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130890,
    events_root: None,
}
2023-01-24T06:35:14.429559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-24T06:35:14.429563Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::12
2023-01-24T06:35:14.429565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.429569Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.429571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.429750Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131274,
    events_root: None,
}
2023-01-24T06:35:14.429763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-24T06:35:14.429767Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::13
2023-01-24T06:35:14.429769Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.429773Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.429775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.429954Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131286,
    events_root: None,
}
2023-01-24T06:35:14.429967Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-24T06:35:14.429970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::15
2023-01-24T06:35:14.429972Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.429976Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.429978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.430158Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131299,
    events_root: None,
}
2023-01-24T06:35:14.430170Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-24T06:35:14.430174Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::16
2023-01-24T06:35:14.430176Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.430180Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.430182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.430371Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3129806,
    events_root: None,
}
2023-01-24T06:35:14.430384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-24T06:35:14.430388Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Berlin::14
2023-01-24T06:35:14.430390Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.430394Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.430396Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.430574Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3132285,
    events_root: None,
}
2023-01-24T06:35:14.430588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:14.430591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::0
2023-01-24T06:35:14.430594Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.430597Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.430599Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.430778Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3129708,
    events_root: None,
}
2023-01-24T06:35:14.430791Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:14.430796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::1
2023-01-24T06:35:14.430799Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.430802Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.430804Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.430982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130514,
    events_root: None,
}
2023-01-24T06:35:14.430995Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:14.430999Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::2
2023-01-24T06:35:14.431001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.431005Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.431007Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.431186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130679,
    events_root: None,
}
2023-01-24T06:35:14.431199Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:35:14.431202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::3
2023-01-24T06:35:14.431205Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.431208Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.431210Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.434255Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 38668279,
    events_root: None,
}
2023-01-24T06:35:14.434269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:35:14.434272Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::4
2023-01-24T06:35:14.434275Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.434278Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.434280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.434475Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103077,
    events_root: None,
}
2023-01-24T06:35:14.434486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T06:35:14.434489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::5
2023-01-24T06:35:14.434493Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.434496Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.434498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.434678Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103099,
    events_root: None,
}
2023-01-24T06:35:14.434689Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T06:35:14.434693Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::6
2023-01-24T06:35:14.434695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.434698Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.434701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.434881Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3104836,
    events_root: None,
}
2023-01-24T06:35:14.434891Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T06:35:14.434894Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::7
2023-01-24T06:35:14.434897Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.434900Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.434902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.435099Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103606,
    events_root: None,
}
2023-01-24T06:35:14.435110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-24T06:35:14.435113Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::8
2023-01-24T06:35:14.435116Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.435119Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.435121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.439254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16649357,
    events_root: None,
}
2023-01-24T06:35:14.439287Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-24T06:35:14.439295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::9
2023-01-24T06:35:14.439299Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.439303Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.439305Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.439585Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130864,
    events_root: None,
}
2023-01-24T06:35:14.439599Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-24T06:35:14.439603Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::10
2023-01-24T06:35:14.439605Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.439609Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.439611Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.439794Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130877,
    events_root: None,
}
2023-01-24T06:35:14.439807Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-24T06:35:14.439811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::11
2023-01-24T06:35:14.439813Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.439816Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.439818Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.439999Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130890,
    events_root: None,
}
2023-01-24T06:35:14.440012Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-24T06:35:14.440016Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::12
2023-01-24T06:35:14.440019Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.440024Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.440026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.440205Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131274,
    events_root: None,
}
2023-01-24T06:35:14.440218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-24T06:35:14.440222Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::13
2023-01-24T06:35:14.440225Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.440228Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.440231Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.440410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131286,
    events_root: None,
}
2023-01-24T06:35:14.440424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-24T06:35:14.440427Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::15
2023-01-24T06:35:14.440430Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.440433Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.440435Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.440615Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131299,
    events_root: None,
}
2023-01-24T06:35:14.440628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-24T06:35:14.440632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::16
2023-01-24T06:35:14.440634Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.440637Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.440639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.440828Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3129806,
    events_root: None,
}
2023-01-24T06:35:14.440841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-24T06:35:14.440844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::London::14
2023-01-24T06:35:14.440847Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.440850Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.440852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.441038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3132285,
    events_root: None,
}
2023-01-24T06:35:14.441052Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:14.441055Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::0
2023-01-24T06:35:14.441058Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.441061Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.441063Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.441243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3129708,
    events_root: None,
}
2023-01-24T06:35:14.441256Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:14.441264Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::1
2023-01-24T06:35:14.441267Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.441270Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.441272Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.441454Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130514,
    events_root: None,
}
2023-01-24T06:35:14.441467Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:14.441471Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::2
2023-01-24T06:35:14.441473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.441476Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.441478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.441657Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130679,
    events_root: None,
}
2023-01-24T06:35:14.441670Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:35:14.441674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::3
2023-01-24T06:35:14.441676Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.441679Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.441681Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.444732Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 38668279,
    events_root: None,
}
2023-01-24T06:35:14.444745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:35:14.444749Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::4
2023-01-24T06:35:14.444752Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.444755Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.444758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.444952Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103077,
    events_root: None,
}
2023-01-24T06:35:14.444963Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T06:35:14.444966Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::5
2023-01-24T06:35:14.444969Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.444973Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.444975Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.445155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103099,
    events_root: None,
}
2023-01-24T06:35:14.445165Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T06:35:14.445168Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::6
2023-01-24T06:35:14.445172Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.445175Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.445177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.445394Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3104836,
    events_root: None,
}
2023-01-24T06:35:14.445405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T06:35:14.445408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::7
2023-01-24T06:35:14.445411Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.445414Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.445416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.445595Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3103606,
    events_root: None,
}
2023-01-24T06:35:14.445605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-24T06:35:14.445609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::8
2023-01-24T06:35:14.445611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.445614Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.445617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.449469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16649357,
    events_root: None,
}
2023-01-24T06:35:14.449502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-24T06:35:14.449510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::9
2023-01-24T06:35:14.449514Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.449518Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.449520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.449790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130864,
    events_root: None,
}
2023-01-24T06:35:14.449804Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-24T06:35:14.449807Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::10
2023-01-24T06:35:14.449810Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.449813Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.449815Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.449996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130877,
    events_root: None,
}
2023-01-24T06:35:14.450009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-24T06:35:14.450012Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::11
2023-01-24T06:35:14.450015Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.450018Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.450020Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.450202Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3130890,
    events_root: None,
}
2023-01-24T06:35:14.450215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-24T06:35:14.450219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::12
2023-01-24T06:35:14.450221Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.450225Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.450227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.450405Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131274,
    events_root: None,
}
2023-01-24T06:35:14.450418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-24T06:35:14.450421Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::13
2023-01-24T06:35:14.450424Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.450427Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.450429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.450608Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131286,
    events_root: None,
}
2023-01-24T06:35:14.450621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-24T06:35:14.450624Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::15
2023-01-24T06:35:14.450627Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.450630Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.450632Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.450811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3131299,
    events_root: None,
}
2023-01-24T06:35:14.450825Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-24T06:35:14.450828Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::16
2023-01-24T06:35:14.450830Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.450834Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.450836Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.451022Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3129806,
    events_root: None,
}
2023-01-24T06:35:14.451035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-24T06:35:14.451038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3"::Merge::14
2023-01-24T06:35:14.451041Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.451044Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.451046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.451230Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3132285,
    events_root: None,
}
2023-01-24T06:35:14.453029Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/sha3.json"
2023-01-24T06:35:14.453067Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.478276Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:14.478381Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.478385Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:14.478439Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.478441Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:14.478499Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.478502Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:14.478556Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.478559Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:14.478611Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.478685Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:14.478690Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::Istanbul::0
2023-01-24T06:35:14.478694Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.478698Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.478700Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.816012Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845575,
    events_root: None,
}
2023-01-24T06:35:14.816035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:14.816042Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::Istanbul::1
2023-01-24T06:35:14.816045Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.816048Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.816050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.816311Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5052694,
    events_root: None,
}
2023-01-24T06:35:14.816322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:14.816325Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::Istanbul::2
2023-01-24T06:35:14.816328Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.816331Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.816333Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.816526Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845575,
    events_root: None,
}
2023-01-24T06:35:14.816537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:14.816540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::Berlin::0
2023-01-24T06:35:14.816543Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.816546Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.816549Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.816713Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2538641,
    events_root: None,
}
2023-01-24T06:35:14.816723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:14.816726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::Berlin::1
2023-01-24T06:35:14.816728Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.816732Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.816734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.816909Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2538641,
    events_root: None,
}
2023-01-24T06:35:14.816919Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:14.816922Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::Berlin::2
2023-01-24T06:35:14.816924Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.816928Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.816930Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.817090Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2538641,
    events_root: None,
}
2023-01-24T06:35:14.817100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:14.817103Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::London::0
2023-01-24T06:35:14.817105Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.817109Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.817111Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.817281Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2538641,
    events_root: None,
}
2023-01-24T06:35:14.817291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:14.817294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::London::1
2023-01-24T06:35:14.817297Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.817300Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.817302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.817462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2538641,
    events_root: None,
}
2023-01-24T06:35:14.817471Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:14.817474Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::London::2
2023-01-24T06:35:14.817477Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.817481Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.817482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.817639Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2538641,
    events_root: None,
}
2023-01-24T06:35:14.817648Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:14.817651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::Merge::0
2023-01-24T06:35:14.817654Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.817657Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.817659Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.817821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2538641,
    events_root: None,
}
2023-01-24T06:35:14.817830Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:14.817833Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::Merge::1
2023-01-24T06:35:14.817836Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.817839Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.817841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.818003Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2538641,
    events_root: None,
}
2023-01-24T06:35:14.818013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:14.818016Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicide"::Merge::2
2023-01-24T06:35:14.818020Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.818024Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.818026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:14.818186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2538641,
    events_root: None,
}
2023-01-24T06:35:14.819831Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/suicide.json"
2023-01-24T06:35:14.819860Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:14.845668Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:35:14.845781Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.845785Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:35:14.845844Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.845847Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T06:35:14.845915Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.845917Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T06:35:14.845972Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.845975Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T06:35:14.846024Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846026Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T06:35:14.846090Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846092Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T06:35:14.846151Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846153Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T06:35:14.846199Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846202Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T06:35:14.846247Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846249Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T06:35:14.846303Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846306Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-24T06:35:14.846355Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846358Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-24T06:35:14.846408Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846410Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-24T06:35:14.846453Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846455Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-24T06:35:14.846500Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846502Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-24T06:35:14.846559Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846563Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-24T06:35:14.846615Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846617Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-24T06:35:14.846662Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846664Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-24T06:35:14.846716Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:35:14.846794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:35:14.846800Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::0
2023-01-24T06:35:14.846803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:14.846807Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:14.846809Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.192281Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.192309Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T06:35:15.192316Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::1
2023-01-24T06:35:15.192319Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.192323Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.192324Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.192665Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.192675Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-24T06:35:15.192678Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::2
2023-01-24T06:35:15.192680Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.192683Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.192684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.193022Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.193033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-24T06:35:15.193035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::3
2023-01-24T06:35:15.193038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.193040Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.193041Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.193381Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.193391Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-24T06:35:15.193394Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::4
2023-01-24T06:35:15.193396Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.193398Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.193400Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.193731Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.193742Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-24T06:35:15.193745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::5
2023-01-24T06:35:15.193747Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.193749Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.193751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.194080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.194091Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-24T06:35:15.194094Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::6
2023-01-24T06:35:15.194096Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.194098Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.194100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.194429Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.194439Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-24T06:35:15.194442Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::7
2023-01-24T06:35:15.194444Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.194446Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.194448Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.194777Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.194787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-24T06:35:15.194790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::8
2023-01-24T06:35:15.194792Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.194795Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.194796Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.195125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.195136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-24T06:35:15.195139Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::9
2023-01-24T06:35:15.195141Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.195143Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.195145Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.195472Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.195483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-24T06:35:15.195486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::10
2023-01-24T06:35:15.195488Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.195490Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.195492Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.195821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.195832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-24T06:35:15.195834Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::11
2023-01-24T06:35:15.195836Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.195839Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.195841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.196169Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.196179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-24T06:35:15.196182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::12
2023-01-24T06:35:15.196184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.196186Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.196188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.196515Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.196526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-24T06:35:15.196530Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::13
2023-01-24T06:35:15.196533Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.196536Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.196537Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.196866Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.196877Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-24T06:35:15.196880Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::14
2023-01-24T06:35:15.196882Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.196884Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.196885Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.197233Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9648839,
    events_root: None,
}
2023-01-24T06:35:15.197244Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-24T06:35:15.197247Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Istanbul::15
2023-01-24T06:35:15.197249Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.197251Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.197253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.197613Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9075223,
    events_root: None,
}
2023-01-24T06:35:15.197624Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T06:35:15.197627Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::0
2023-01-24T06:35:15.197629Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.197632Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.197634Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.197953Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.197964Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T06:35:15.197967Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::1
2023-01-24T06:35:15.197968Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.197971Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.197972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.198285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.198296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-24T06:35:15.198299Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::2
2023-01-24T06:35:15.198301Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.198304Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.198306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.198618Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.198628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-24T06:35:15.198631Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::3
2023-01-24T06:35:15.198633Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.198636Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.198637Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.198948Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.198959Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-24T06:35:15.198962Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::4
2023-01-24T06:35:15.198964Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.198966Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.198968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.199281Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.199291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-24T06:35:15.199294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::5
2023-01-24T06:35:15.199296Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.199298Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.199300Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.199612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.199622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-24T06:35:15.199625Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::6
2023-01-24T06:35:15.199627Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.199629Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.199631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.199942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.199953Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-24T06:35:15.199956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::7
2023-01-24T06:35:15.199958Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.199960Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.199962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.200275Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.200286Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-24T06:35:15.200288Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::8
2023-01-24T06:35:15.200290Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.200293Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.200294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.200605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.200615Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-24T06:35:15.200618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::9
2023-01-24T06:35:15.200620Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.200623Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.200624Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.200936Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.200947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-24T06:35:15.200949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::10
2023-01-24T06:35:15.200951Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.200953Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.200955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.201275Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.201285Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-24T06:35:15.201288Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::11
2023-01-24T06:35:15.201289Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.201292Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.201294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.201616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.201628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-24T06:35:15.201631Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::12
2023-01-24T06:35:15.201634Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.201637Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.201639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.201993Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.202006Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-24T06:35:15.202010Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::13
2023-01-24T06:35:15.202012Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.202016Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.202018Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.202351Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.202361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-24T06:35:15.202364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::14
2023-01-24T06:35:15.202366Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.202368Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.202370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.202686Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.202697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-24T06:35:15.202700Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Berlin::15
2023-01-24T06:35:15.202702Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.202704Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.202706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.203021Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6564348,
    events_root: None,
}
2023-01-24T06:35:15.203032Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T06:35:15.203035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::0
2023-01-24T06:35:15.203036Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.203040Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.203042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.203444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.203456Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T06:35:15.203458Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::1
2023-01-24T06:35:15.203460Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.203463Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.203464Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.203821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.203832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-24T06:35:15.203835Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::2
2023-01-24T06:35:15.203837Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.203839Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.203840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.204267Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.204282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-24T06:35:15.204286Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::3
2023-01-24T06:35:15.204289Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.204292Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.204294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.204704Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.204717Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-24T06:35:15.204719Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::4
2023-01-24T06:35:15.204721Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.204724Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.204725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.205095Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.205108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-24T06:35:15.205111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::5
2023-01-24T06:35:15.205114Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.205117Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.205119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.205537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.205551Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-24T06:35:15.205555Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::6
2023-01-24T06:35:15.205557Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.205560Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.205561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.205972Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.205986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-24T06:35:15.205990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::7
2023-01-24T06:35:15.205993Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.205996Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.205998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.206418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.206432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-24T06:35:15.206435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::8
2023-01-24T06:35:15.206438Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.206441Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.206443Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.206850Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.206861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-24T06:35:15.206863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::9
2023-01-24T06:35:15.206866Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.206868Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.206869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.207189Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.207200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-24T06:35:15.207202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::10
2023-01-24T06:35:15.207205Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.207207Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.207208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.207552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.207562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-24T06:35:15.207565Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::11
2023-01-24T06:35:15.207567Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.207569Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.207571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.207887Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.207898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-24T06:35:15.207901Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::12
2023-01-24T06:35:15.207903Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.207905Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.207906Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.208244Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.208256Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-24T06:35:15.208259Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::13
2023-01-24T06:35:15.208261Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.208263Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.208264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.208580Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.208590Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-24T06:35:15.208593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::14
2023-01-24T06:35:15.208595Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.208597Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.208598Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.208940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.208950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-24T06:35:15.208953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::London::15
2023-01-24T06:35:15.208955Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.208957Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.208959Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.209279Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6564348,
    events_root: None,
}
2023-01-24T06:35:15.209291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T06:35:15.209293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::0
2023-01-24T06:35:15.209296Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.209298Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.209299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.209618Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.209628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T06:35:15.209631Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::1
2023-01-24T06:35:15.209633Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.209635Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.209637Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.209973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.209984Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-24T06:35:15.209986Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::2
2023-01-24T06:35:15.209989Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.209991Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.209992Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.210305Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.210315Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-24T06:35:15.210318Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::3
2023-01-24T06:35:15.210320Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.210322Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.210324Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.210661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.210672Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-24T06:35:15.210675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::4
2023-01-24T06:35:15.210677Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.210679Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.210681Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.210995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.211006Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-24T06:35:15.211009Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::5
2023-01-24T06:35:15.211011Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.211013Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.211014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.211352Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.211362Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-24T06:35:15.211365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::6
2023-01-24T06:35:15.211367Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.211370Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.211371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.211686Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.211696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-24T06:35:15.211699Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::7
2023-01-24T06:35:15.211701Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.211703Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.211705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.212039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.212050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-24T06:35:15.212052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::8
2023-01-24T06:35:15.212054Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.212057Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.212058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.212372Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.212383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-24T06:35:15.212385Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::9
2023-01-24T06:35:15.212387Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.212390Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.212391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.212726Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.212736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-24T06:35:15.212739Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::10
2023-01-24T06:35:15.212741Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.212743Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.212745Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.213068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.213079Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-24T06:35:15.213082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::11
2023-01-24T06:35:15.213084Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.213086Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.213088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.213436Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.213447Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-24T06:35:15.213450Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::12
2023-01-24T06:35:15.213452Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.213455Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.213457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.213771Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.213783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-24T06:35:15.213786Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::13
2023-01-24T06:35:15.213788Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.213791Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.213792Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.214128Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.214139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-24T06:35:15.214141Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::14
2023-01-24T06:35:15.214143Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.214145Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.214147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.214461Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6841007,
    events_root: None,
}
2023-01-24T06:35:15.214472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-24T06:35:15.214475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "swap"::Merge::15
2023-01-24T06:35:15.214477Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.214480Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T06:35:15.214481Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T06:35:15.214813Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6564348,
    events_root: None,
}
2023-01-24T06:35:15.216418Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmTests/swap.json"
2023-01-24T06:35:15.216533Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 11 Files in Time:4.035633012s
```