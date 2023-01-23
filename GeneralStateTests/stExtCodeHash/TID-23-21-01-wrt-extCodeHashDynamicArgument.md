> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json#L12

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json \
	cargo run \
	-- \
	statetest
```

> For Review

* Execution looks OK, No "failed to create the new actor :: cannot create address with a reserved prefix" error observed.

> Opcodes

```
0000 PUSH1 0x00
0002 CALLDATALOAD
0003 EXTCODEHASH
0004 PUSH1 0x00
0006 SSTORE
0007 PUSH1 0x00
0009 CALLDATALOAD
000a EXTCODESIZE
000b PUSH1 0x01
000d SSTORE
000e STOP
```


> Execution Trace

```
2023-01-23T08:38:58.900442Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json", Total Files :: 1
2023-01-23T08:38:58.900882Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:38:59.241991Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T08:38:59.245673Z  WARN evm_eth_compliance::statetest::runner: Skipping Pre Test test_name: '"extCodeHashDynamicArgument"', owner_address: '0x0000000000000000000000000000000000000002'
2023-01-23T08:38:59.245690Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T08:38:59.247210Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:38:59.247225Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T08:38:59.248437Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:38:59.248451Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T08:38:59.249542Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:38:59.249557Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T08:38:59.250745Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T08:38:59.251906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T08:38:59.251940Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::0
2023-01-23T08:38:59.251952Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:38:59.251961Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:38:59.251968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.063500Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2525038,
    events_root: None,
}
2023-01-23T08:39:07.063559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T08:39:07.063606Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::1
2023-01-23T08:39:07.063614Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.063621Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.063628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.064225Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1581719,
    events_root: None,
}
2023-01-23T08:39:07.064251Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T08:39:07.064278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::2
2023-01-23T08:39:07.064285Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.064292Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.064298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.066237Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6261758,
    events_root: None,
}
2023-01-23T08:39:07.066284Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T08:39:07.066309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::3
2023-01-23T08:39:07.066316Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.066323Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.066329Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.068190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6510279,
    events_root: None,
}
2023-01-23T08:39:07.068235Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T08:39:07.068260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::4
2023-01-23T08:39:07.068268Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.068277Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.068283Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.069443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2515406,
    events_root: None,
}
2023-01-23T08:39:07.069475Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T08:39:07.069499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::0
2023-01-23T08:39:07.069506Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.069513Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.069519Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.070261Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2525038,
    events_root: None,
}
2023-01-23T08:39:07.070294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T08:39:07.070318Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::1
2023-01-23T08:39:07.070325Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.070332Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.070338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.070893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1581719,
    events_root: None,
}
2023-01-23T08:39:07.070919Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T08:39:07.070943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::2
2023-01-23T08:39:07.070950Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.070957Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.070963Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.072807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6261758,
    events_root: None,
}
2023-01-23T08:39:07.072851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T08:39:07.072875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::3
2023-01-23T08:39:07.072882Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.072889Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.072895Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.074731Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6510279,
    events_root: None,
}
2023-01-23T08:39:07.074774Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T08:39:07.074798Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::4
2023-01-23T08:39:07.074805Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.074812Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.074818Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.075899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2515406,
    events_root: None,
}
2023-01-23T08:39:07.075930Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T08:39:07.075953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::0
2023-01-23T08:39:07.075960Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.075967Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.075973Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.076654Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2525038,
    events_root: None,
}
2023-01-23T08:39:07.076682Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T08:39:07.076706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::1
2023-01-23T08:39:07.076713Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.076720Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.076726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.077271Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1581719,
    events_root: None,
}
2023-01-23T08:39:07.077299Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T08:39:07.077321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::2
2023-01-23T08:39:07.077328Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.077335Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.077341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.079144Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6261758,
    events_root: None,
}
2023-01-23T08:39:07.079187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T08:39:07.079210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::3
2023-01-23T08:39:07.079217Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.079224Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.079230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.081091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6510279,
    events_root: None,
}
2023-01-23T08:39:07.081134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T08:39:07.081158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::4
2023-01-23T08:39:07.081165Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.081172Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.081178Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.082266Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2515406,
    events_root: None,
}
2023-01-23T08:39:07.082296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T08:39:07.082319Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::0
2023-01-23T08:39:07.082326Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.082334Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.082340Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.083016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2525038,
    events_root: None,
}
2023-01-23T08:39:07.083045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T08:39:07.083068Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::1
2023-01-23T08:39:07.083075Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.083082Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.083088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.083635Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1581719,
    events_root: None,
}
2023-01-23T08:39:07.083662Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T08:39:07.083685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::2
2023-01-23T08:39:07.083692Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.083699Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.083705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.085543Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6261758,
    events_root: None,
}
2023-01-23T08:39:07.085586Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T08:39:07.085609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::3
2023-01-23T08:39:07.085616Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.085623Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.085629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.087515Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6510279,
    events_root: None,
}
2023-01-23T08:39:07.087559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T08:39:07.087583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::4
2023-01-23T08:39:07.087590Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.087597Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-23T08:39:07.087603Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T08:39:07.088702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2515406,
    events_root: None,
}
2023-01-23T08:39:07.090961Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-23T08:39:07.091310Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:7.846767162s
```