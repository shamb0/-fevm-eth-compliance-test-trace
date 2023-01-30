> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stEIP158Specific

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stEIP158Specific \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case are skipped due to `transaction.tx` empty. Have to re-check on revm

| Test ID | Use-Case |
| --- | --- |
| TID-18-07 | vitalikTransactionTest |

> Execution Trace

```
2023-01-26T11:43:40.729119Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_OneVCallSuicide.json", Total Files :: 1
2023-01-26T11:43:40.772672Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:43:40.772849Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:40.772853Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:43:40.772906Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:40.772908Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:43:40.772967Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:40.773037Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T11:43:40.773040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CALL_OneVCallSuicide"::Istanbul::0
2023-01-26T11:43:40.773043Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_OneVCallSuicide.json"
2023-01-26T11:43:40.773046Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:40.773047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:41.123048Z  INFO evm_eth_compliance::statetest::runner: UC : "CALL_OneVCallSuicide"
2023-01-26T11:43:41.123064Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2739690,
    events_root: None,
}
2023-01-26T11:43:41.123075Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:43:41.123081Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CALL_OneVCallSuicide"::Berlin::0
2023-01-26T11:43:41.123083Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_OneVCallSuicide.json"
2023-01-26T11:43:41.123086Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:41.123087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:41.123224Z  INFO evm_eth_compliance::statetest::runner: UC : "CALL_OneVCallSuicide"
2023-01-26T11:43:41.123229Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1836499,
    events_root: None,
}
2023-01-26T11:43:41.123235Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:43:41.123238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CALL_OneVCallSuicide"::London::0
2023-01-26T11:43:41.123241Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_OneVCallSuicide.json"
2023-01-26T11:43:41.123244Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:41.123245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:41.123368Z  INFO evm_eth_compliance::statetest::runner: UC : "CALL_OneVCallSuicide"
2023-01-26T11:43:41.123372Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1836499,
    events_root: None,
}
2023-01-26T11:43:41.123377Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:43:41.123380Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CALL_OneVCallSuicide"::Merge::0
2023-01-26T11:43:41.123382Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_OneVCallSuicide.json"
2023-01-26T11:43:41.123384Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:41.123385Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:41.123506Z  INFO evm_eth_compliance::statetest::runner: UC : "CALL_OneVCallSuicide"
2023-01-26T11:43:41.123510Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1836499,
    events_root: None,
}
2023-01-26T11:43:41.125144Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:350.848733ms
2023-01-26T11:43:41.403958Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_ZeroVCallSuicide.json", Total Files :: 1
2023-01-26T11:43:41.437920Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:43:41.438109Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:41.438113Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:43:41.438171Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:41.438173Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:43:41.438235Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:41.438310Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T11:43:41.438313Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CALL_ZeroVCallSuicide"::Istanbul::0
2023-01-26T11:43:41.438317Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_ZeroVCallSuicide.json"
2023-01-26T11:43:41.438320Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:41.438322Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:41.790160Z  INFO evm_eth_compliance::statetest::runner: UC : "CALL_ZeroVCallSuicide"
2023-01-26T11:43:41.790174Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2734166,
    events_root: None,
}
2023-01-26T11:43:41.790186Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:43:41.790191Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CALL_ZeroVCallSuicide"::Berlin::0
2023-01-26T11:43:41.790192Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_ZeroVCallSuicide.json"
2023-01-26T11:43:41.790195Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:41.790197Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:41.790325Z  INFO evm_eth_compliance::statetest::runner: UC : "CALL_ZeroVCallSuicide"
2023-01-26T11:43:41.790329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1830975,
    events_root: None,
}
2023-01-26T11:43:41.790335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:43:41.790338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CALL_ZeroVCallSuicide"::London::0
2023-01-26T11:43:41.790340Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_ZeroVCallSuicide.json"
2023-01-26T11:43:41.790342Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:41.790343Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:41.790455Z  INFO evm_eth_compliance::statetest::runner: UC : "CALL_ZeroVCallSuicide"
2023-01-26T11:43:41.790460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1830975,
    events_root: None,
}
2023-01-26T11:43:41.790465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:43:41.790468Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CALL_ZeroVCallSuicide"::Merge::0
2023-01-26T11:43:41.790470Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/CALL_ZeroVCallSuicide.json"
2023-01-26T11:43:41.790473Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:41.790474Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:41.790584Z  INFO evm_eth_compliance::statetest::runner: UC : "CALL_ZeroVCallSuicide"
2023-01-26T11:43:41.790588Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1830975,
    events_root: None,
}
2023-01-26T11:43:41.792157Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.678367ms
2023-01-26T11:43:42.071240Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXP_Empty.json", Total Files :: 1
2023-01-26T11:43:42.101156Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:43:42.101337Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:42.101341Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:43:42.101405Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:42.101479Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T11:43:42.101482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXP_Empty"::Istanbul::0
2023-01-26T11:43:42.101485Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXP_Empty.json"
2023-01-26T11:43:42.101487Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:42.101489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:42.462376Z  INFO evm_eth_compliance::statetest::runner: UC : "EXP_Empty"
2023-01-26T11:43:42.462392Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8800116,
    events_root: None,
}
2023-01-26T11:43:42.462406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:43:42.462414Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXP_Empty"::Berlin::0
2023-01-26T11:43:42.462416Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXP_Empty.json"
2023-01-26T11:43:42.462419Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:42.462424Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:42.462778Z  INFO evm_eth_compliance::statetest::runner: UC : "EXP_Empty"
2023-01-26T11:43:42.462783Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10418415,
    events_root: None,
}
2023-01-26T11:43:42.462793Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:43:42.462797Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXP_Empty"::London::0
2023-01-26T11:43:42.462799Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXP_Empty.json"
2023-01-26T11:43:42.462803Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:42.462805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:42.463108Z  INFO evm_eth_compliance::statetest::runner: UC : "EXP_Empty"
2023-01-26T11:43:42.463113Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9256723,
    events_root: None,
}
2023-01-26T11:43:42.463124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:43:42.463128Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXP_Empty"::Merge::0
2023-01-26T11:43:42.463130Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXP_Empty.json"
2023-01-26T11:43:42.463134Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:42.463136Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:42.463443Z  INFO evm_eth_compliance::statetest::runner: UC : "EXP_Empty"
2023-01-26T11:43:42.463448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9258739,
    events_root: None,
}
2023-01-26T11:43:42.465133Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.307713ms
2023-01-26T11:43:42.760308Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toEpmty.json", Total Files :: 1
2023-01-26T11:43:42.790320Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:43:42.790505Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:42.790509Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:43:42.790564Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:42.790567Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:43:42.790628Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:42.790703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T11:43:42.790706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXTCODESIZE_toEpmty"::Istanbul::0
2023-01-26T11:43:42.790709Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toEpmty.json"
2023-01-26T11:43:42.790712Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:42.790714Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:43.183378Z  INFO evm_eth_compliance::statetest::runner: UC : "EXTCODESIZE_toEpmty"
2023-01-26T11:43:43.183393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3675041,
    events_root: None,
}
2023-01-26T11:43:43.183405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:43:43.183411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXTCODESIZE_toEpmty"::Berlin::0
2023-01-26T11:43:43.183413Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toEpmty.json"
2023-01-26T11:43:43.183417Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:43.183418Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:43.183613Z  INFO evm_eth_compliance::statetest::runner: UC : "EXTCODESIZE_toEpmty"
2023-01-26T11:43:43.183617Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3692177,
    events_root: None,
}
2023-01-26T11:43:43.183625Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:43:43.183628Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXTCODESIZE_toEpmty"::London::0
2023-01-26T11:43:43.183630Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toEpmty.json"
2023-01-26T11:43:43.183632Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:43.183634Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:43.183799Z  INFO evm_eth_compliance::statetest::runner: UC : "EXTCODESIZE_toEpmty"
2023-01-26T11:43:43.183804Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2773198,
    events_root: None,
}
2023-01-26T11:43:43.183811Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:43:43.183814Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXTCODESIZE_toEpmty"::Merge::0
2023-01-26T11:43:43.183816Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toEpmty.json"
2023-01-26T11:43:43.183818Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:43.183820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:43.183983Z  INFO evm_eth_compliance::statetest::runner: UC : "EXTCODESIZE_toEpmty"
2023-01-26T11:43:43.183987Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2773198,
    events_root: None,
}
2023-01-26T11:43:43.185674Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:393.67967ms
2023-01-26T11:43:43.456236Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toNonExistent.json", Total Files :: 1
2023-01-26T11:43:43.486291Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:43:43.486501Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:43.486506Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:43:43.486572Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:43.486651Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T11:43:43.486654Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXTCODESIZE_toNonExistent"::Istanbul::0
2023-01-26T11:43:43.486657Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toNonExistent.json"
2023-01-26T11:43:43.486661Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:43.486662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:43.849427Z  INFO evm_eth_compliance::statetest::runner: UC : "EXTCODESIZE_toNonExistent"
2023-01-26T11:43:43.849450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2526448,
    events_root: None,
}
2023-01-26T11:43:43.849464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:43:43.849472Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXTCODESIZE_toNonExistent"::Berlin::0
2023-01-26T11:43:43.849474Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toNonExistent.json"
2023-01-26T11:43:43.849478Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:43.849479Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:43.849659Z  INFO evm_eth_compliance::statetest::runner: UC : "EXTCODESIZE_toNonExistent"
2023-01-26T11:43:43.849663Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2543798,
    events_root: None,
}
2023-01-26T11:43:43.849669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:43:43.849672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXTCODESIZE_toNonExistent"::London::0
2023-01-26T11:43:43.849675Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toNonExistent.json"
2023-01-26T11:43:43.849677Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:43.849680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:43.849792Z  INFO evm_eth_compliance::statetest::runner: UC : "EXTCODESIZE_toNonExistent"
2023-01-26T11:43:43.849797Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1626121,
    events_root: None,
}
2023-01-26T11:43:43.849803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:43:43.849806Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EXTCODESIZE_toNonExistent"::Merge::0
2023-01-26T11:43:43.849808Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/EXTCODESIZE_toNonExistent.json"
2023-01-26T11:43:43.849812Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:43.849816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:43.849931Z  INFO evm_eth_compliance::statetest::runner: UC : "EXTCODESIZE_toNonExistent"
2023-01-26T11:43:43.849936Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1626121,
    events_root: None,
}
2023-01-26T11:43:43.852113Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.656812ms
2023-01-26T11:43:44.131179Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP158Specific/callToEmptyThenCallError.json", Total Files :: 1
2023-01-26T11:43:44.161028Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:43:44.161213Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:44.161217Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:43:44.161276Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:44.161279Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:43:44.161349Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:44.161352Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T11:43:44.161415Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:44.161489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T11:43:44.161494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToEmptyThenCallError"::Istanbul::0
2023-01-26T11:43:44.161497Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/callToEmptyThenCallError.json"
2023-01-26T11:43:44.161502Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:44.161504Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:44.541931Z  INFO evm_eth_compliance::statetest::runner: UC : "callToEmptyThenCallError"
2023-01-26T11:43:44.541948Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1879633,
    events_root: None,
}
2023-01-26T11:43:44.541961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:43:44.541968Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToEmptyThenCallError"::Berlin::0
2023-01-26T11:43:44.541970Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/callToEmptyThenCallError.json"
2023-01-26T11:43:44.541974Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:44.541976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:44.542145Z  INFO evm_eth_compliance::statetest::runner: UC : "callToEmptyThenCallError"
2023-01-26T11:43:44.542150Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1879633,
    events_root: None,
}
2023-01-26T11:43:44.542158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:43:44.542161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToEmptyThenCallError"::London::0
2023-01-26T11:43:44.542164Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/callToEmptyThenCallError.json"
2023-01-26T11:43:44.542169Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:44.542170Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:44.542293Z  INFO evm_eth_compliance::statetest::runner: UC : "callToEmptyThenCallError"
2023-01-26T11:43:44.542298Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1879633,
    events_root: None,
}
2023-01-26T11:43:44.542305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:43:44.542308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToEmptyThenCallError"::Merge::0
2023-01-26T11:43:44.542310Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/callToEmptyThenCallError.json"
2023-01-26T11:43:44.542313Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T11:43:44.542315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T11:43:44.542449Z  INFO evm_eth_compliance::statetest::runner: UC : "callToEmptyThenCallError"
2023-01-26T11:43:44.542454Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1879633,
    events_root: None,
}
2023-01-26T11:43:44.544505Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:381.439406ms
2023-01-26T11:43:44.827447Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP158Specific/vitalikTransactionTest.json", Total Files :: 1
2023-01-26T11:43:44.856965Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T11:43:44.857148Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:44.857152Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T11:43:44.857207Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:44.857209Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T11:43:44.857268Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T11:43:44.857341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T11:43:44.857380Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "vitalikTransactionTest"::Istanbul::0
2023-01-26T11:43:44.857383Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/vitalikTransactionTest.json"
2023-01-26T11:43:44.857386Z  WARN evm_eth_compliance::statetest::runner: TX len : 268
2023-01-26T11:43:44.857388Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T11:43:44.857390Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "vitalikTransactionTest"::Berlin::0
2023-01-26T11:43:44.857391Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/vitalikTransactionTest.json"
2023-01-26T11:43:44.857394Z  WARN evm_eth_compliance::statetest::runner: TX len : 268
2023-01-26T11:43:44.857395Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T11:43:44.857397Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "vitalikTransactionTest"::London::0
2023-01-26T11:43:44.857398Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/vitalikTransactionTest.json"
2023-01-26T11:43:44.857401Z  WARN evm_eth_compliance::statetest::runner: TX len : 268
2023-01-26T11:43:44.857402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T11:43:44.857404Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "vitalikTransactionTest"::Merge::0
2023-01-26T11:43:44.857405Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP158Specific/vitalikTransactionTest.json"
2023-01-26T11:43:44.857408Z  WARN evm_eth_compliance::statetest::runner: TX len : 268
2023-01-26T11:43:44.858165Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:448.908s
```