> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/VMTests/vmArithmeticTest

> For Review

* Execution looks OK. No error observed

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T15:53:50.991078Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest", Total Files :: 19
2023-01-23T15:53:50.991324Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.021194Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:51.021442Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.021449Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:51.021507Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.021510Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:51.021590Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.021594Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:51.021676Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.021679Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:51.021732Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.021734Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:51.021802Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.021803Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:51.021870Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.021953Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:51.021957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Istanbul::0
2023-01-23T15:53:51.021959Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.021963Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.021964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.360701Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4001048,
    events_root: None,
}
2023-01-23T15:53:51.360728Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:51.360734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Istanbul::1
2023-01-23T15:53:51.360736Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.360739Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.360741Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.360930Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955628,
    events_root: None,
}
2023-01-23T15:53:51.360941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:51.360944Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Istanbul::2
2023-01-23T15:53:51.360945Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.360948Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.360950Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.361114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030837,
    events_root: None,
}
2023-01-23T15:53:51.361122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:51.361124Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Istanbul::3
2023-01-23T15:53:51.361126Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.361129Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.361130Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.361294Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029619,
    events_root: None,
}
2023-01-23T15:53:51.361302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:51.361305Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Istanbul::4
2023-01-23T15:53:51.361307Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.361309Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.361311Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.361473Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030837,
    events_root: None,
}
2023-01-23T15:53:51.361481Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:51.361484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Berlin::0
2023-01-23T15:53:51.361485Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.361488Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.361489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.361669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062313,
    events_root: None,
}
2023-01-23T15:53:51.361677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:51.361679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Berlin::1
2023-01-23T15:53:51.361681Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.361683Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.361685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.361853Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060406,
    events_root: None,
}
2023-01-23T15:53:51.361861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:51.361864Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Berlin::2
2023-01-23T15:53:51.361866Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.361868Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.361869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.362030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030837,
    events_root: None,
}
2023-01-23T15:53:51.362038Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:51.362041Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Berlin::3
2023-01-23T15:53:51.362043Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.362045Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.362046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.362208Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029619,
    events_root: None,
}
2023-01-23T15:53:51.362216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:51.362219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Berlin::4
2023-01-23T15:53:51.362220Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.362223Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.362224Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.362385Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030837,
    events_root: None,
}
2023-01-23T15:53:51.362393Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:51.362395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::London::0
2023-01-23T15:53:51.362397Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.362400Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.362401Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.362566Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062313,
    events_root: None,
}
2023-01-23T15:53:51.362574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:51.362576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::London::1
2023-01-23T15:53:51.362578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.362581Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.362582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.362747Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060406,
    events_root: None,
}
2023-01-23T15:53:51.362755Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:51.362757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::London::2
2023-01-23T15:53:51.362759Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.362761Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.362763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.362924Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030837,
    events_root: None,
}
2023-01-23T15:53:51.362932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:51.362935Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::London::3
2023-01-23T15:53:51.362937Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.362939Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.362940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.363101Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029619,
    events_root: None,
}
2023-01-23T15:53:51.363109Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:51.363112Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::London::4
2023-01-23T15:53:51.363113Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.363117Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.363118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.363280Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030837,
    events_root: None,
}
2023-01-23T15:53:51.363288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:51.363291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Merge::0
2023-01-23T15:53:51.363293Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.363295Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.363296Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.363461Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062313,
    events_root: None,
}
2023-01-23T15:53:51.363469Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:51.363471Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Merge::1
2023-01-23T15:53:51.363473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.363476Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.363477Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.363641Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060406,
    events_root: None,
}
2023-01-23T15:53:51.363650Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:51.363652Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Merge::2
2023-01-23T15:53:51.363654Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.363656Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.363658Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.363819Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030837,
    events_root: None,
}
2023-01-23T15:53:51.363827Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:51.363830Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Merge::3
2023-01-23T15:53:51.363832Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.363834Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.363835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.363997Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029619,
    events_root: None,
}
2023-01-23T15:53:51.364005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:51.364007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "add"::Merge::4
2023-01-23T15:53:51.364009Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.364012Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.364013Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.364174Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030837,
    events_root: None,
}
2023-01-23T15:53:51.365886Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/add.json"
2023-01-23T15:53:51.365916Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.391865Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:51.391971Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.391976Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:51.392028Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392029Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:51.392086Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392087Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:51.392139Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392142Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:51.392193Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392196Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:51.392258Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392260Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:51.392315Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392317Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:53:51.392360Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392362Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T15:53:51.392403Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392405Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T15:53:51.392457Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392459Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T15:53:51.392505Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392506Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-23T15:53:51.392559Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392561Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-23T15:53:51.392603Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392605Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-23T15:53:51.392647Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392649Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-23T15:53:51.392704Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392707Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-23T15:53:51.392758Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392760Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-23T15:53:51.392804Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392806Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-23T15:53:51.392855Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.392924Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:51.392929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::0
2023-01-23T15:53:51.392932Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.392935Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.392936Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.743863Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3963395,
    events_root: None,
}
2023-01-23T15:53:51.743886Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:51.743892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::1
2023-01-23T15:53:51.743894Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.743897Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.743898Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.744091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4011998,
    events_root: None,
}
2023-01-23T15:53:51.744100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:51.744102Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::2
2023-01-23T15:53:51.744104Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.744107Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.744108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.744287Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003667,
    events_root: None,
}
2023-01-23T15:53:51.744296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:51.744298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::3
2023-01-23T15:53:51.744300Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.744303Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.744304Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.744471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043553,
    events_root: None,
}
2023-01-23T15:53:51.744479Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:51.744481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::4
2023-01-23T15:53:51.744483Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.744486Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.744487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.744650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042965,
    events_root: None,
}
2023-01-23T15:53:51.744658Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:51.744660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::5
2023-01-23T15:53:51.744662Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.744665Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.744666Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.744842Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3959654,
    events_root: None,
}
2023-01-23T15:53:51.744850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-23T15:53:51.744853Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::6
2023-01-23T15:53:51.744854Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.744857Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.744858Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.745036Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3036506,
    events_root: None,
}
2023-01-23T15:53:51.745046Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-23T15:53:51.745048Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::7
2023-01-23T15:53:51.745050Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.745053Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.745054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.745237Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003667,
    events_root: None,
}
2023-01-23T15:53:51.745247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-23T15:53:51.745249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::8
2023-01-23T15:53:51.745251Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.745254Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.745255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.745422Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034931,
    events_root: None,
}
2023-01-23T15:53:51.745431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-23T15:53:51.745433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::9
2023-01-23T15:53:51.745435Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.745437Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.745439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.745620Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3959722,
    events_root: None,
}
2023-01-23T15:53:51.745636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-23T15:53:51.745639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::10
2023-01-23T15:53:51.745641Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.745643Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.745645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.745830Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3966601,
    events_root: None,
}
2023-01-23T15:53:51.745839Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-23T15:53:51.745842Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::11
2023-01-23T15:53:51.745844Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.745847Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.745848Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.746015Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034350,
    events_root: None,
}
2023-01-23T15:53:51.746024Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-23T15:53:51.746027Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::12
2023-01-23T15:53:51.746029Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.746031Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.746033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.746197Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.746205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-23T15:53:51.746208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::13
2023-01-23T15:53:51.746210Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.746212Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.746213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.746378Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.746386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-23T15:53:51.746389Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::14
2023-01-23T15:53:51.746391Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.746393Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.746394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.746565Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.746573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-23T15:53:51.746576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Istanbul::15
2023-01-23T15:53:51.746578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.746580Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.746581Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.746761Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000935,
    events_root: None,
}
2023-01-23T15:53:51.746770Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:51.746772Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::0
2023-01-23T15:53:51.746774Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.746776Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.746778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.746949Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067808,
    events_root: None,
}
2023-01-23T15:53:51.746957Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:51.746960Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::1
2023-01-23T15:53:51.746962Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.746964Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.746966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.747134Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3073788,
    events_root: None,
}
2023-01-23T15:53:51.747143Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:51.747145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::2
2023-01-23T15:53:51.747147Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.747150Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.747151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.747319Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065457,
    events_root: None,
}
2023-01-23T15:53:51.747327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:51.747330Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::3
2023-01-23T15:53:51.747332Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.747334Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.747335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.747501Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043553,
    events_root: None,
}
2023-01-23T15:53:51.747510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:51.747512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::4
2023-01-23T15:53:51.747514Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.747517Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.747518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.747682Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042965,
    events_root: None,
}
2023-01-23T15:53:51.747691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:51.747694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::5
2023-01-23T15:53:51.747696Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.747698Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.747700Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.747867Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064431,
    events_root: None,
}
2023-01-23T15:53:51.747876Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-23T15:53:51.747878Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::6
2023-01-23T15:53:51.747880Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.747883Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.747884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.748057Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3036506,
    events_root: None,
}
2023-01-23T15:53:51.748066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-23T15:53:51.748069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::7
2023-01-23T15:53:51.748071Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.748073Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.748075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.748243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065457,
    events_root: None,
}
2023-01-23T15:53:51.748252Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-23T15:53:51.748254Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::8
2023-01-23T15:53:51.748257Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.748259Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.748260Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.748424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034931,
    events_root: None,
}
2023-01-23T15:53:51.748434Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-23T15:53:51.748437Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::9
2023-01-23T15:53:51.748440Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.748442Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.748443Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.748609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064499,
    events_root: None,
}
2023-01-23T15:53:51.748618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-23T15:53:51.748620Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::10
2023-01-23T15:53:51.748622Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.748625Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.748627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.748794Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071379,
    events_root: None,
}
2023-01-23T15:53:51.748802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-23T15:53:51.748805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::11
2023-01-23T15:53:51.748807Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.748809Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.748810Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.748973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034350,
    events_root: None,
}
2023-01-23T15:53:51.748982Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-23T15:53:51.748984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::12
2023-01-23T15:53:51.748986Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.748988Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.748990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.749152Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.749161Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-23T15:53:51.749163Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::13
2023-01-23T15:53:51.749165Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.749168Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.749169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.749332Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.749340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-23T15:53:51.749342Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::14
2023-01-23T15:53:51.749344Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.749347Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.749348Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.749525Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.749534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-23T15:53:51.749536Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Berlin::15
2023-01-23T15:53:51.749538Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.749541Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.749542Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.749718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062725,
    events_root: None,
}
2023-01-23T15:53:51.749727Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:51.749729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::0
2023-01-23T15:53:51.749731Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.749734Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.749735Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.749902Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067808,
    events_root: None,
}
2023-01-23T15:53:51.749911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:51.749913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::1
2023-01-23T15:53:51.749915Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.749918Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.749919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.750086Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3073788,
    events_root: None,
}
2023-01-23T15:53:51.750095Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:51.750097Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::2
2023-01-23T15:53:51.750099Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.750102Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.750103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.750270Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065457,
    events_root: None,
}
2023-01-23T15:53:51.750278Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:51.750281Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::3
2023-01-23T15:53:51.750283Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.750286Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.750287Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.750453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043553,
    events_root: None,
}
2023-01-23T15:53:51.750461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:51.750464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::4
2023-01-23T15:53:51.750466Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.750469Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.750471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.750634Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042965,
    events_root: None,
}
2023-01-23T15:53:51.750642Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:51.750645Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::5
2023-01-23T15:53:51.750647Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.750649Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.750651Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.750815Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064431,
    events_root: None,
}
2023-01-23T15:53:51.750824Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T15:53:51.750826Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::6
2023-01-23T15:53:51.750829Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.750831Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.750833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.750994Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3036506,
    events_root: None,
}
2023-01-23T15:53:51.751003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T15:53:51.751005Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::7
2023-01-23T15:53:51.751007Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.751010Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.751011Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.751181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065457,
    events_root: None,
}
2023-01-23T15:53:51.751190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T15:53:51.751192Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::8
2023-01-23T15:53:51.751194Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.751197Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.751199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.751362Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034931,
    events_root: None,
}
2023-01-23T15:53:51.751370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-23T15:53:51.751373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::9
2023-01-23T15:53:51.751375Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.751377Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.751379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.751544Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064499,
    events_root: None,
}
2023-01-23T15:53:51.751553Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-23T15:53:51.751555Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::10
2023-01-23T15:53:51.751557Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.751560Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.751561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.751727Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071379,
    events_root: None,
}
2023-01-23T15:53:51.751736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-23T15:53:51.751738Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::11
2023-01-23T15:53:51.751740Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.751743Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.751744Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.751907Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034350,
    events_root: None,
}
2023-01-23T15:53:51.751915Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-23T15:53:51.751918Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::12
2023-01-23T15:53:51.751920Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.751923Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.751924Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.752085Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.752094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-23T15:53:51.752097Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::13
2023-01-23T15:53:51.752099Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.752101Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.752103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.752263Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.752272Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-23T15:53:51.752275Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::14
2023-01-23T15:53:51.752276Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.752279Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.752280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.752442Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.752450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-23T15:53:51.752453Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::London::15
2023-01-23T15:53:51.752455Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.752457Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.752458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.752633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062725,
    events_root: None,
}
2023-01-23T15:53:51.752642Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:51.752644Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::0
2023-01-23T15:53:51.752646Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.752650Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.752651Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.752819Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067808,
    events_root: None,
}
2023-01-23T15:53:51.752827Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:51.752830Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::1
2023-01-23T15:53:51.752832Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.752834Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.752835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.753002Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3073788,
    events_root: None,
}
2023-01-23T15:53:51.753011Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:51.753014Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::2
2023-01-23T15:53:51.753016Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.753018Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.753019Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.753185Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065457,
    events_root: None,
}
2023-01-23T15:53:51.753193Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:51.753196Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::3
2023-01-23T15:53:51.753198Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.753200Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.753202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.753366Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043553,
    events_root: None,
}
2023-01-23T15:53:51.753375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:51.753377Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::4
2023-01-23T15:53:51.753379Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.753382Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.753383Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.753545Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3042965,
    events_root: None,
}
2023-01-23T15:53:51.753553Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:51.753556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::5
2023-01-23T15:53:51.753558Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.753561Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.753562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.753744Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064431,
    events_root: None,
}
2023-01-23T15:53:51.753753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T15:53:51.753755Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::6
2023-01-23T15:53:51.753758Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.753760Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.753761Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.753926Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3036506,
    events_root: None,
}
2023-01-23T15:53:51.753935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T15:53:51.753937Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::7
2023-01-23T15:53:51.753939Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.753942Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.753943Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.754114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065457,
    events_root: None,
}
2023-01-23T15:53:51.754123Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T15:53:51.754126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::8
2023-01-23T15:53:51.754128Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.754131Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.754132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.754297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034931,
    events_root: None,
}
2023-01-23T15:53:51.754305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-23T15:53:51.754308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::9
2023-01-23T15:53:51.754310Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.754312Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.754313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.754480Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064499,
    events_root: None,
}
2023-01-23T15:53:51.754488Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-23T15:53:51.754491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::10
2023-01-23T15:53:51.754493Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.754496Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.754497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.754663Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071379,
    events_root: None,
}
2023-01-23T15:53:51.754672Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-23T15:53:51.754674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::11
2023-01-23T15:53:51.754676Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.754678Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.754680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.754843Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034350,
    events_root: None,
}
2023-01-23T15:53:51.754851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-23T15:53:51.754853Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::12
2023-01-23T15:53:51.754856Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.754859Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.754860Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.755036Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.755047Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-23T15:53:51.755050Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::13
2023-01-23T15:53:51.755052Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.755056Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.755057Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.755276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.755288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-23T15:53:51.755291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::14
2023-01-23T15:53:51.755294Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.755297Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.755299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.755547Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:51.755559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-23T15:53:51.755562Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmod"::Merge::15
2023-01-23T15:53:51.755565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.755569Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:51.755571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:51.755776Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062725,
    events_root: None,
}
2023-01-23T15:53:51.757262Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/addmod.json"
2023-01-23T15:53:51.757291Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/arith.json"
2023-01-23T15:53:51.782136Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:51.782237Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.782240Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:51.782293Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:51.782362Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:51.782366Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "arith"::Istanbul::0
2023-01-23T15:53:51.782368Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/arith.json"
2023-01-23T15:53:51.782371Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:51.782373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.120994Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 480000000000000000 },
    gas_used: 2531593,
    events_root: None,
}
2023-01-23T15:53:52.121020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:52.121029Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "arith"::Berlin::0
2023-01-23T15:53:52.121032Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/arith.json"
2023-01-23T15:53:52.121036Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:52.121037Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.121182Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 480000000000000000 },
    gas_used: 1633718,
    events_root: None,
}
2023-01-23T15:53:52.121191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:52.121194Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "arith"::London::0
2023-01-23T15:53:52.121197Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/arith.json"
2023-01-23T15:53:52.121200Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:52.121203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.121326Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 480000000000000000 },
    gas_used: 1633718,
    events_root: None,
}
2023-01-23T15:53:52.121335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:52.121338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "arith"::Merge::0
2023-01-23T15:53:52.121340Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/arith.json"
2023-01-23T15:53:52.121343Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:52.121345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.121463Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 480000000000000000 },
    gas_used: 1633718,
    events_root: None,
}
2023-01-23T15:53:52.122765Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/arith.json"
2023-01-23T15:53:52.122798Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.149851Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:52.149976Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.149980Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:52.150037Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.150040Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:52.150099Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.150101Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:52.150157Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.150160Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:52.150215Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.150218Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:52.150283Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.150286Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:52.150344Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.150346Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:53:52.150394Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.150397Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T15:53:52.150442Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.150445Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T15:53:52.150500Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.150580Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:52.150585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Istanbul::0
2023-01-23T15:53:52.150589Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.150593Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.150594Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.509555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031325,
    events_root: None,
}
2023-01-23T15:53:52.509578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:52.509585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Istanbul::3
2023-01-23T15:53:52.509587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.509591Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.509592Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.509789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032559,
    events_root: None,
}
2023-01-23T15:53:52.509798Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:52.509801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Istanbul::4
2023-01-23T15:53:52.509803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.509805Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.509807Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.509978Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030179,
    events_root: None,
}
2023-01-23T15:53:52.509987Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-23T15:53:52.509990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Istanbul::6
2023-01-23T15:53:52.509991Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.509994Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.509995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.510167Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029427,
    events_root: None,
}
2023-01-23T15:53:52.510175Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:52.510178Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Istanbul::1
2023-01-23T15:53:52.510180Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.510182Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.510184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.510381Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3966695,
    events_root: None,
}
2023-01-23T15:53:52.510390Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:52.510392Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Istanbul::2
2023-01-23T15:53:52.510395Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.510397Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.510398Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.510587Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3957350,
    events_root: None,
}
2023-01-23T15:53:52.510596Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:52.510598Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Istanbul::5
2023-01-23T15:53:52.510600Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.510603Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.510604Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.510789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3957350,
    events_root: None,
}
2023-01-23T15:53:52.510798Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-23T15:53:52.510801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Istanbul::7
2023-01-23T15:53:52.510803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.510806Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.510807Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.510995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3956021,
    events_root: None,
}
2023-01-23T15:53:52.511005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:52.511007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Berlin::0
2023-01-23T15:53:52.511009Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.511011Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.511013Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.511181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031325,
    events_root: None,
}
2023-01-23T15:53:52.511190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:52.511192Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Berlin::3
2023-01-23T15:53:52.511194Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.511197Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.511198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.511367Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032559,
    events_root: None,
}
2023-01-23T15:53:52.511375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:52.511378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Berlin::4
2023-01-23T15:53:52.511380Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.511382Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.511383Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.511549Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030179,
    events_root: None,
}
2023-01-23T15:53:52.511557Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-23T15:53:52.511560Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Berlin::6
2023-01-23T15:53:52.511562Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.511565Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.511567Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.511734Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029427,
    events_root: None,
}
2023-01-23T15:53:52.511742Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:52.511745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Berlin::1
2023-01-23T15:53:52.511747Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.511749Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.511751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.511927Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071472,
    events_root: None,
}
2023-01-23T15:53:52.511935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:52.511938Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Berlin::2
2023-01-23T15:53:52.511939Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.511942Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.511943Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.512114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061763,
    events_root: None,
}
2023-01-23T15:53:52.512123Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:52.512125Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Berlin::5
2023-01-23T15:53:52.512127Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.512130Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.512131Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.512302Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061763,
    events_root: None,
}
2023-01-23T15:53:52.512310Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-23T15:53:52.512313Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Berlin::7
2023-01-23T15:53:52.512315Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.512317Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.512319Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.512490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060435,
    events_root: None,
}
2023-01-23T15:53:52.512498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:52.512500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::London::0
2023-01-23T15:53:52.512503Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.512505Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.512507Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.512675Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031325,
    events_root: None,
}
2023-01-23T15:53:52.512683Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:52.512685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::London::3
2023-01-23T15:53:52.512687Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.512690Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.512691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.512861Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032559,
    events_root: None,
}
2023-01-23T15:53:52.512870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:52.512873Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::London::4
2023-01-23T15:53:52.512876Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.512879Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.512880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.513052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030179,
    events_root: None,
}
2023-01-23T15:53:52.513060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T15:53:52.513063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::London::6
2023-01-23T15:53:52.513065Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.513067Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.513069Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.513235Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029427,
    events_root: None,
}
2023-01-23T15:53:52.513243Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:52.513245Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::London::1
2023-01-23T15:53:52.513247Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.513250Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.513251Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.513425Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071472,
    events_root: None,
}
2023-01-23T15:53:52.513433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:52.513436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::London::2
2023-01-23T15:53:52.513438Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.513440Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.513441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.513612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061763,
    events_root: None,
}
2023-01-23T15:53:52.513621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:52.513624Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::London::5
2023-01-23T15:53:52.513631Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.513634Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.513636Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.513816Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061763,
    events_root: None,
}
2023-01-23T15:53:52.513824Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T15:53:52.513827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::London::7
2023-01-23T15:53:52.513829Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.513832Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.513833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.514005Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060435,
    events_root: None,
}
2023-01-23T15:53:52.514013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:52.514015Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Merge::0
2023-01-23T15:53:52.514017Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.514020Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.514021Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.514190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031325,
    events_root: None,
}
2023-01-23T15:53:52.514199Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:52.514201Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Merge::3
2023-01-23T15:53:52.514203Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.514206Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.514207Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.514374Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032559,
    events_root: None,
}
2023-01-23T15:53:52.514382Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:52.514385Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Merge::4
2023-01-23T15:53:52.514387Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.514389Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.514391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.514557Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030179,
    events_root: None,
}
2023-01-23T15:53:52.514566Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T15:53:52.514568Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Merge::6
2023-01-23T15:53:52.514570Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.514573Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.514574Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.514741Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029427,
    events_root: None,
}
2023-01-23T15:53:52.514750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:52.514753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Merge::1
2023-01-23T15:53:52.514754Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.514757Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.514758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.514932Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071472,
    events_root: None,
}
2023-01-23T15:53:52.514940Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:52.514943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Merge::2
2023-01-23T15:53:52.514945Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.514947Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.514948Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.515120Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061763,
    events_root: None,
}
2023-01-23T15:53:52.515128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:52.515130Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Merge::5
2023-01-23T15:53:52.515132Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.515135Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.515136Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.515304Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061763,
    events_root: None,
}
2023-01-23T15:53:52.515312Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T15:53:52.515315Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "div"::Merge::7
2023-01-23T15:53:52.515317Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.515319Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.515321Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.515504Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060435,
    events_root: None,
}
2023-01-23T15:53:52.516988Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/div.json"
2023-01-23T15:53:52.517018Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.543887Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:52.543995Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.543999Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:52.544054Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.544124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:52.544128Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::0
2023-01-23T15:53:52.544130Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.544133Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.544135Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.923917Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.923938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:52.923945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::1
2023-01-23T15:53:52.923948Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.923950Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.923952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.924077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.924084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:52.924086Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::2
2023-01-23T15:53:52.924088Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.924091Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.924093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.924187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.924194Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:52.924196Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::3
2023-01-23T15:53:52.924198Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.924201Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.924202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.924294Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.924300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:52.924303Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::4
2023-01-23T15:53:52.924304Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.924308Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.924309Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.924401Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.924407Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:52.924410Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::5
2023-01-23T15:53:52.924412Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.924414Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.924416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.924506Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.924513Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-23T15:53:52.924515Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::6
2023-01-23T15:53:52.924517Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.924519Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.924521Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.924611Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.924619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-23T15:53:52.924621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::7
2023-01-23T15:53:52.924623Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.924625Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.924627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.924719Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.924725Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-23T15:53:52.924728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::8
2023-01-23T15:53:52.924729Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.924732Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.924733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.924823Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.924830Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-23T15:53:52.924833Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::9
2023-01-23T15:53:52.924834Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.924836Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.924838Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.924933Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594184,
    events_root: None,
}
2023-01-23T15:53:52.924939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-23T15:53:52.924941Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::10
2023-01-23T15:53:52.924943Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.924946Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.924947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925045Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.925051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-23T15:53:52.925053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::11
2023-01-23T15:53:52.925055Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.925058Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.925059Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925150Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.925156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-23T15:53:52.925159Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::12
2023-01-23T15:53:52.925160Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.925164Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.925165Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.925261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-23T15:53:52.925263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::13
2023-01-23T15:53:52.925265Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.925268Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.925269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925359Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594288,
    events_root: None,
}
2023-01-23T15:53:52.925365Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-23T15:53:52.925367Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::14
2023-01-23T15:53:52.925369Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.925371Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.925373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.925469Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-23T15:53:52.925471Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::15
2023-01-23T15:53:52.925474Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.925476Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.925477Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925567Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.925573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 16
2023-01-23T15:53:52.925575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::16
2023-01-23T15:53:52.925577Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.925580Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.925581Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925680Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.925687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 17
2023-01-23T15:53:52.925689Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::17
2023-01-23T15:53:52.925691Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.925694Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.925695Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925787Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.925794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 18
2023-01-23T15:53:52.925796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::18
2023-01-23T15:53:52.925798Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.925800Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.925802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925896Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.925902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 19
2023-01-23T15:53:52.925904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::19
2023-01-23T15:53:52.925906Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.925908Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.925910Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.925999Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.926006Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 20
2023-01-23T15:53:52.926008Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::20
2023-01-23T15:53:52.926009Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926012Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.926013Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.926103Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.926109Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 21
2023-01-23T15:53:52.926112Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::21
2023-01-23T15:53:52.926114Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926117Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.926118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.926209Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.926215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 22
2023-01-23T15:53:52.926217Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::22
2023-01-23T15:53:52.926219Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926221Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.926223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.926312Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.926318Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 23
2023-01-23T15:53:52.926320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::23
2023-01-23T15:53:52.926323Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926326Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.926327Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.926415Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594184,
    events_root: None,
}
2023-01-23T15:53:52.926422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 24
2023-01-23T15:53:52.926424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::24
2023-01-23T15:53:52.926426Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926429Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.926430Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.926520Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.926526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 25
2023-01-23T15:53:52.926528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::25
2023-01-23T15:53:52.926530Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926532Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.926533Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.926629Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.926635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 26
2023-01-23T15:53:52.926637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::26
2023-01-23T15:53:52.926639Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926642Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.926643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.926739Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.926750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 27
2023-01-23T15:53:52.926752Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::27
2023-01-23T15:53:52.926754Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926756Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.926757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.926866Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594276,
    events_root: None,
}
2023-01-23T15:53:52.926874Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 28
2023-01-23T15:53:52.926876Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::28
2023-01-23T15:53:52.926878Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926880Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.926882Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.926975Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.926981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 29
2023-01-23T15:53:52.926983Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::29
2023-01-23T15:53:52.926985Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.926987Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.926989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.927079Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.927085Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 30
2023-01-23T15:53:52.927088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::30
2023-01-23T15:53:52.927090Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.927092Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.927094Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.927184Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.927190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 31
2023-01-23T15:53:52.927192Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::31
2023-01-23T15:53:52.927194Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.927196Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.927198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.927286Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.927293Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 32
2023-01-23T15:53:52.927295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::32
2023-01-23T15:53:52.927297Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.927300Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.927302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.927391Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.927398Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 33
2023-01-23T15:53:52.927400Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::33
2023-01-23T15:53:52.927402Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.927405Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.927406Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.927498Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.927504Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 34
2023-01-23T15:53:52.927507Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::34
2023-01-23T15:53:52.927509Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.927511Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.927513Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.927606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.927613Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 35
2023-01-23T15:53:52.927615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::35
2023-01-23T15:53:52.927617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.927619Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.927620Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.927712Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.927720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 36
2023-01-23T15:53:52.927722Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::36
2023-01-23T15:53:52.927725Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.927728Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.927730Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.927821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.927827Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 37
2023-01-23T15:53:52.927829Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::37
2023-01-23T15:53:52.927831Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.927834Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.927835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.927925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.927931Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 38
2023-01-23T15:53:52.927933Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::38
2023-01-23T15:53:52.927935Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.927937Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.927939Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928028Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.928036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 39
2023-01-23T15:53:52.928038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::39
2023-01-23T15:53:52.928040Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.928042Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.928044Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928134Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.928140Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 40
2023-01-23T15:53:52.928142Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::40
2023-01-23T15:53:52.928144Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.928146Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.928148Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928237Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.928244Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 41
2023-01-23T15:53:52.928246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::41
2023-01-23T15:53:52.928249Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.928251Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.928253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928362Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.928370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 42
2023-01-23T15:53:52.928373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::42
2023-01-23T15:53:52.928375Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.928377Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.928379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928474Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.928480Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 43
2023-01-23T15:53:52.928482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::43
2023-01-23T15:53:52.928484Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.928487Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.928488Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928576Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.928584Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 44
2023-01-23T15:53:52.928586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::44
2023-01-23T15:53:52.928588Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.928591Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.928592Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928685Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.928691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 45
2023-01-23T15:53:52.928693Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::45
2023-01-23T15:53:52.928695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.928697Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.928699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928788Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.928795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 46
2023-01-23T15:53:52.928798Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::46
2023-01-23T15:53:52.928800Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.928802Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.928804Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.928900Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 47
2023-01-23T15:53:52.928902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::47
2023-01-23T15:53:52.928904Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.928906Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.928907Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.928996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929002Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 48
2023-01-23T15:53:52.929004Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::48
2023-01-23T15:53:52.929007Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929009Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929011Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.929099Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 49
2023-01-23T15:53:52.929108Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::49
2023-01-23T15:53:52.929109Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929112Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929113Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.929202Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929208Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 50
2023-01-23T15:53:52.929210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::50
2023-01-23T15:53:52.929212Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929214Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929216Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.929308Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929316Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 51
2023-01-23T15:53:52.929318Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::51
2023-01-23T15:53:52.929320Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929323Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929324Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.929420Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 52
2023-01-23T15:53:52.929431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::52
2023-01-23T15:53:52.929434Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929437Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.929531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 53
2023-01-23T15:53:52.929539Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::53
2023-01-23T15:53:52.929541Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929543Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.929641Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929648Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 54
2023-01-23T15:53:52.929651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::54
2023-01-23T15:53:52.929653Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929656Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929657Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.929749Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929755Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 55
2023-01-23T15:53:52.929757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::55
2023-01-23T15:53:52.929759Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929761Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.929851Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929857Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 56
2023-01-23T15:53:52.929860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::56
2023-01-23T15:53:52.929863Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929866Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929867Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.929956Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.929963Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 57
2023-01-23T15:53:52.929965Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::57
2023-01-23T15:53:52.929967Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.929969Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.929970Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.930059Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.930066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 58
2023-01-23T15:53:52.930068Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::58
2023-01-23T15:53:52.930070Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.930072Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.930074Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.930164Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.930172Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 59
2023-01-23T15:53:52.930174Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::59
2023-01-23T15:53:52.930176Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.930180Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.930181Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.930273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.930279Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 60
2023-01-23T15:53:52.930281Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::60
2023-01-23T15:53:52.930283Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.930286Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.930287Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.930376Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.930383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 61
2023-01-23T15:53:52.930386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::61
2023-01-23T15:53:52.930387Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.930390Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.930391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.930481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.930487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 62
2023-01-23T15:53:52.930490Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::62
2023-01-23T15:53:52.930491Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.930494Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.930495Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.930584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.930591Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 63
2023-01-23T15:53:52.930594Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::63
2023-01-23T15:53:52.930596Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.930599Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.930601Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.930690Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.930696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 64
2023-01-23T15:53:52.930698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::64
2023-01-23T15:53:52.930700Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.930702Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.930704Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.930792Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.930798Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 65
2023-01-23T15:53:52.930801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::65
2023-01-23T15:53:52.930803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.930805Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.930806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.930894Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.930902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 66
2023-01-23T15:53:52.930904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::66
2023-01-23T15:53:52.930906Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.930908Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.930910Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931004Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931010Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 67
2023-01-23T15:53:52.931013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::67
2023-01-23T15:53:52.931014Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931017Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931018Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931113Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 68
2023-01-23T15:53:52.931122Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::68
2023-01-23T15:53:52.931124Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931127Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931128Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931217Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 69
2023-01-23T15:53:52.931226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::69
2023-01-23T15:53:52.931228Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931230Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931320Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 70
2023-01-23T15:53:52.931330Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::70
2023-01-23T15:53:52.931332Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931334Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 71
2023-01-23T15:53:52.931433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::71
2023-01-23T15:53:52.931435Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931437Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931528Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 72
2023-01-23T15:53:52.931536Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::72
2023-01-23T15:53:52.931538Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931541Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931543Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931632Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 73
2023-01-23T15:53:52.931641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::73
2023-01-23T15:53:52.931643Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931645Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 74
2023-01-23T15:53:52.931745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::74
2023-01-23T15:53:52.931747Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931749Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931843Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 75
2023-01-23T15:53:52.931853Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::75
2023-01-23T15:53:52.931855Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931857Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931858Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.931949Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.931955Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 76
2023-01-23T15:53:52.931957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::76
2023-01-23T15:53:52.931959Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.931962Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.931964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.932053Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.932061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 77
2023-01-23T15:53:52.932063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::77
2023-01-23T15:53:52.932065Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.932068Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.932069Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.932157Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.932164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 78
2023-01-23T15:53:52.932166Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::78
2023-01-23T15:53:52.932168Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.932170Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.932171Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.932261Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.932267Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 79
2023-01-23T15:53:52.932270Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::79
2023-01-23T15:53:52.932272Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.932274Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.932276Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.932365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.932372Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 80
2023-01-23T15:53:52.932374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::80
2023-01-23T15:53:52.932376Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.932378Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.932379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.932468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.932474Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 81
2023-01-23T15:53:52.932476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::81
2023-01-23T15:53:52.932478Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.932481Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.932482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.932571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.932577Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 82
2023-01-23T15:53:52.932580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::82
2023-01-23T15:53:52.932582Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.932584Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.932586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.932695Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.932703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 83
2023-01-23T15:53:52.932706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::83
2023-01-23T15:53:52.932708Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.932711Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.932713Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.932810Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.932816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 84
2023-01-23T15:53:52.932818Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::84
2023-01-23T15:53:52.932820Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.932822Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.932824Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.932915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.932921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 85
2023-01-23T15:53:52.932923Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::85
2023-01-23T15:53:52.932925Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.932927Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.932929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.933018Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.933024Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 86
2023-01-23T15:53:52.933027Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::86
2023-01-23T15:53:52.933028Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.933031Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.933032Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.933122Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.933128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 87
2023-01-23T15:53:52.933131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::87
2023-01-23T15:53:52.933133Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.933135Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.933137Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.933226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.933232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 88
2023-01-23T15:53:52.933235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::88
2023-01-23T15:53:52.933237Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.933239Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.933240Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.933330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.933336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 89
2023-01-23T15:53:52.933338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::89
2023-01-23T15:53:52.933341Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.933344Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.933345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.933434Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.933440Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 90
2023-01-23T15:53:52.933443Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::90
2023-01-23T15:53:52.933444Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.933447Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.933448Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.933541Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.933547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 91
2023-01-23T15:53:52.933550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::91
2023-01-23T15:53:52.933552Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.933554Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.933555Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.933656Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.933663Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 92
2023-01-23T15:53:52.933665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::92
2023-01-23T15:53:52.933667Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.933670Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.933671Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.933763Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.933772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 93
2023-01-23T15:53:52.933775Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::93
2023-01-23T15:53:52.933777Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.933781Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.933783Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.933902Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.933910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 94
2023-01-23T15:53:52.933912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::94
2023-01-23T15:53:52.933915Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.933918Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.933920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.934049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.934056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 95
2023-01-23T15:53:52.934059Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::95
2023-01-23T15:53:52.934061Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.934063Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.934064Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.934180Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.934188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 96
2023-01-23T15:53:52.934191Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::96
2023-01-23T15:53:52.934194Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.934199Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.934201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.934301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.934307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 97
2023-01-23T15:53:52.934309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Istanbul::97
2023-01-23T15:53:52.934311Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.934314Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.934315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.934405Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.934412Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:52.934415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::0
2023-01-23T15:53:52.934416Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.934419Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.934420Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.934511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.934517Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:52.934519Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::1
2023-01-23T15:53:52.934521Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.934524Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.934525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.934618Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.934629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:52.934632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::2
2023-01-23T15:53:52.934634Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.934638Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.934639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.934758Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.934766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:52.934769Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::3
2023-01-23T15:53:52.934771Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.934775Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.934776Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.934895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.934904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:52.934908Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::4
2023-01-23T15:53:52.934911Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.934914Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.934916Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.935047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.935057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:52.935061Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::5
2023-01-23T15:53:52.935064Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.935067Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.935069Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.935198Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.935206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-23T15:53:52.935209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::6
2023-01-23T15:53:52.935212Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.935215Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.935217Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.935336Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.935344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-23T15:53:52.935347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::7
2023-01-23T15:53:52.935349Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.935352Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.935356Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.935480Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.935489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-23T15:53:52.935492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::8
2023-01-23T15:53:52.935495Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.935498Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.935500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.935630Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.935639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-23T15:53:52.935642Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::9
2023-01-23T15:53:52.935645Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.935648Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.935650Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.935783Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594184,
    events_root: None,
}
2023-01-23T15:53:52.935792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-23T15:53:52.935796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::10
2023-01-23T15:53:52.935799Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.935802Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.935804Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.935934Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.935942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-23T15:53:52.935946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::11
2023-01-23T15:53:52.935949Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.935952Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.935954Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.936068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.936075Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-23T15:53:52.936078Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::12
2023-01-23T15:53:52.936080Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.936082Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.936084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.936176Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.936184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-23T15:53:52.936186Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::13
2023-01-23T15:53:52.936188Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.936190Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.936192Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.936282Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594288,
    events_root: None,
}
2023-01-23T15:53:52.936288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-23T15:53:52.936290Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::14
2023-01-23T15:53:52.936292Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.936295Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.936297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.936385Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.936393Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-23T15:53:52.936395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::15
2023-01-23T15:53:52.936398Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.936400Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.936402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.936491Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.936498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-23T15:53:52.936500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::16
2023-01-23T15:53:52.936501Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.936504Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.936505Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.936595Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.936602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-23T15:53:52.936604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::17
2023-01-23T15:53:52.936606Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.936610Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.936611Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.936702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.936708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-23T15:53:52.936710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::18
2023-01-23T15:53:52.936712Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.936714Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.936715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.936804Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.936810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-23T15:53:52.936813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::19
2023-01-23T15:53:52.936814Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.936817Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.936819Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.936908Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.936915Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 20
2023-01-23T15:53:52.936918Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::20
2023-01-23T15:53:52.936919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.936922Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.936923Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.937019Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 21
2023-01-23T15:53:52.937022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::21
2023-01-23T15:53:52.937023Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937026Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.937027Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.937123Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 22
2023-01-23T15:53:52.937126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::22
2023-01-23T15:53:52.937128Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937131Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.937132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.937227Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 23
2023-01-23T15:53:52.937229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::23
2023-01-23T15:53:52.937231Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937234Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.937235Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937325Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594184,
    events_root: None,
}
2023-01-23T15:53:52.937332Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 24
2023-01-23T15:53:52.937334Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::24
2023-01-23T15:53:52.937336Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937338Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.937340Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937434Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.937440Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 25
2023-01-23T15:53:52.937442Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::25
2023-01-23T15:53:52.937444Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937447Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.937448Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937539Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.937545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 26
2023-01-23T15:53:52.937547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::26
2023-01-23T15:53:52.937549Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937553Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.937554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937652Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.937659Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 27
2023-01-23T15:53:52.937661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::27
2023-01-23T15:53:52.937663Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937666Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.937667Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937758Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594276,
    events_root: None,
}
2023-01-23T15:53:52.937764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 28
2023-01-23T15:53:52.937766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::28
2023-01-23T15:53:52.937769Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937772Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.937773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937863Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.937870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 29
2023-01-23T15:53:52.937872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::29
2023-01-23T15:53:52.937874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937876Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.937878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.937966Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.937972Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 30
2023-01-23T15:53:52.937975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::30
2023-01-23T15:53:52.937976Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.937980Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.937981Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938069Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.938076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 31
2023-01-23T15:53:52.938078Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::31
2023-01-23T15:53:52.938080Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.938083Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.938084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938173Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.938179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 32
2023-01-23T15:53:52.938181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::32
2023-01-23T15:53:52.938183Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.938185Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.938187Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938274Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.938281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 33
2023-01-23T15:53:52.938283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::33
2023-01-23T15:53:52.938286Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.938288Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.938289Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.938384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 34
2023-01-23T15:53:52.938386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::34
2023-01-23T15:53:52.938388Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.938390Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.938391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938479Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.938486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 35
2023-01-23T15:53:52.938488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::35
2023-01-23T15:53:52.938490Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.938492Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.938494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938582Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.938589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 36
2023-01-23T15:53:52.938592Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::36
2023-01-23T15:53:52.938594Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.938596Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.938597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938687Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.938693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 37
2023-01-23T15:53:52.938695Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::37
2023-01-23T15:53:52.938697Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.938700Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.938701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.938796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 38
2023-01-23T15:53:52.938798Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::38
2023-01-23T15:53:52.938800Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.938803Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.938805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.938901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 39
2023-01-23T15:53:52.938903Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::39
2023-01-23T15:53:52.938905Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.938907Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.938909Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.938996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939002Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 40
2023-01-23T15:53:52.939004Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::40
2023-01-23T15:53:52.939006Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939009Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939010Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.939099Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 41
2023-01-23T15:53:52.939107Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::41
2023-01-23T15:53:52.939109Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939113Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939114Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.939202Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939208Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 42
2023-01-23T15:53:52.939210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::42
2023-01-23T15:53:52.939212Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939214Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939215Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.939304Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939310Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 43
2023-01-23T15:53:52.939312Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::43
2023-01-23T15:53:52.939314Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939316Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.939407Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 44
2023-01-23T15:53:52.939416Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::44
2023-01-23T15:53:52.939418Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939420Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.939511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939517Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 45
2023-01-23T15:53:52.939519Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::45
2023-01-23T15:53:52.939521Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939523Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.939611Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 46
2023-01-23T15:53:52.939619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::46
2023-01-23T15:53:52.939621Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939624Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939626Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.939718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939725Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 47
2023-01-23T15:53:52.939727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::47
2023-01-23T15:53:52.939729Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939732Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.939836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939843Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 48
2023-01-23T15:53:52.939846Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::48
2023-01-23T15:53:52.939848Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939850Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.939942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.939948Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 49
2023-01-23T15:53:52.939951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::49
2023-01-23T15:53:52.939952Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.939955Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.939956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940044Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 50
2023-01-23T15:53:52.940052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::50
2023-01-23T15:53:52.940055Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940057Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940059Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940146Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 51
2023-01-23T15:53:52.940155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::51
2023-01-23T15:53:52.940157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940159Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940248Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940254Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 52
2023-01-23T15:53:52.940257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::52
2023-01-23T15:53:52.940258Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940261Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940262Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940349Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 53
2023-01-23T15:53:52.940357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::53
2023-01-23T15:53:52.940360Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940362Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940452Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940459Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 54
2023-01-23T15:53:52.940461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::54
2023-01-23T15:53:52.940463Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940465Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 55
2023-01-23T15:53:52.940564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::55
2023-01-23T15:53:52.940566Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940568Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940570Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940658Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 56
2023-01-23T15:53:52.940667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::56
2023-01-23T15:53:52.940669Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940671Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940673Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940761Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 57
2023-01-23T15:53:52.940770Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::57
2023-01-23T15:53:52.940772Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940774Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940864Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 58
2023-01-23T15:53:52.940872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::58
2023-01-23T15:53:52.940874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940877Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.940967Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.940974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 59
2023-01-23T15:53:52.940977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::59
2023-01-23T15:53:52.940978Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.940981Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.940982Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.941071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.941077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 60
2023-01-23T15:53:52.941079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::60
2023-01-23T15:53:52.941081Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.941083Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.941085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.941174Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.941180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 61
2023-01-23T15:53:52.941182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::61
2023-01-23T15:53:52.941184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.941187Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.941189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.941277Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.941283Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 62
2023-01-23T15:53:52.941285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::62
2023-01-23T15:53:52.941287Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.941289Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.941291Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.941378Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.941384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 63
2023-01-23T15:53:52.941387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::63
2023-01-23T15:53:52.941388Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.941391Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.941392Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.941481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.941487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 64
2023-01-23T15:53:52.941490Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::64
2023-01-23T15:53:52.941492Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.941495Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.941496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.941585Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.941591Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 65
2023-01-23T15:53:52.941593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::65
2023-01-23T15:53:52.941595Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.941598Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.941599Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.941694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.941701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 66
2023-01-23T15:53:52.941705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::66
2023-01-23T15:53:52.941706Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.941709Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.941710Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.941799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.941805Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 67
2023-01-23T15:53:52.941807Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::67
2023-01-23T15:53:52.941809Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.941811Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.941813Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.941907Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.941914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 68
2023-01-23T15:53:52.941916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::68
2023-01-23T15:53:52.941918Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.941921Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.941923Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.942012Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.942018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 69
2023-01-23T15:53:52.942020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::69
2023-01-23T15:53:52.942022Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.942025Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.942026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.942114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.942120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 70
2023-01-23T15:53:52.942123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::70
2023-01-23T15:53:52.942125Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.942127Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.942129Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.942217Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.942224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 71
2023-01-23T15:53:52.942226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::71
2023-01-23T15:53:52.942228Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.942230Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.942232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.942320Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.942326Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 72
2023-01-23T15:53:52.942328Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::72
2023-01-23T15:53:52.942330Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.942333Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.942334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.942421Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.942428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 73
2023-01-23T15:53:52.942431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::73
2023-01-23T15:53:52.942435Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.942438Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.942440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.942548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.942555Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 74
2023-01-23T15:53:52.942559Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::74
2023-01-23T15:53:52.942561Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.942563Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.942564Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.942670Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.942679Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 75
2023-01-23T15:53:52.942682Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::75
2023-01-23T15:53:52.942685Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.942688Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.942690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.942813Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.942823Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 76
2023-01-23T15:53:52.942827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::76
2023-01-23T15:53:52.942829Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.942832Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.942834Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.942961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.942970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 77
2023-01-23T15:53:52.942973Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::77
2023-01-23T15:53:52.942976Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.942978Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.942980Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.943108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.943117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 78
2023-01-23T15:53:52.943121Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::78
2023-01-23T15:53:52.943123Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.943127Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.943129Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.943254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.943263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 79
2023-01-23T15:53:52.943267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::79
2023-01-23T15:53:52.943269Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.943273Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.943275Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.943399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.943408Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 80
2023-01-23T15:53:52.943413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::80
2023-01-23T15:53:52.943416Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.943419Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.943422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.943550Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.943559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 81
2023-01-23T15:53:52.943563Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::81
2023-01-23T15:53:52.943565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.943569Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.943571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.943697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.943706Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 82
2023-01-23T15:53:52.943709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::82
2023-01-23T15:53:52.943712Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.943715Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.943719Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.943834Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.943842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 83
2023-01-23T15:53:52.943844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::83
2023-01-23T15:53:52.943846Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.943849Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.943850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.943941Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.943947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 84
2023-01-23T15:53:52.943950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::84
2023-01-23T15:53:52.943951Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.943954Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.943955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944044Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 85
2023-01-23T15:53:52.944052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::85
2023-01-23T15:53:52.944055Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944058Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944059Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944154Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 86
2023-01-23T15:53:52.944156Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::86
2023-01-23T15:53:52.944158Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944160Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944162Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944249Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944255Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 87
2023-01-23T15:53:52.944257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::87
2023-01-23T15:53:52.944259Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944262Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944352Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944358Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 88
2023-01-23T15:53:52.944361Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::88
2023-01-23T15:53:52.944363Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944365Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944455Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 89
2023-01-23T15:53:52.944463Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::89
2023-01-23T15:53:52.944465Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944468Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944469Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944556Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 90
2023-01-23T15:53:52.944565Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::90
2023-01-23T15:53:52.944566Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944569Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944659Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 91
2023-01-23T15:53:52.944668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::91
2023-01-23T15:53:52.944670Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944673Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944762Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944769Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 92
2023-01-23T15:53:52.944771Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::92
2023-01-23T15:53:52.944773Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944775Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944865Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 93
2023-01-23T15:53:52.944873Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::93
2023-01-23T15:53:52.944875Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944878Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.944968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.944975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 94
2023-01-23T15:53:52.944977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::94
2023-01-23T15:53:52.944979Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.944981Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.944982Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.945071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.945077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 95
2023-01-23T15:53:52.945079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::95
2023-01-23T15:53:52.945081Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.945084Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.945085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.945173Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.945179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 96
2023-01-23T15:53:52.945182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::96
2023-01-23T15:53:52.945184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.945186Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.945188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.945276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.945282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 97
2023-01-23T15:53:52.945284Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Berlin::97
2023-01-23T15:53:52.945288Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.945290Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.945292Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.945379Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.945386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:52.945388Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::0
2023-01-23T15:53:52.945390Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.945393Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.945394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.945482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.945489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:52.945492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::1
2023-01-23T15:53:52.945494Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.945496Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.945498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.945586Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.945592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:52.945595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::2
2023-01-23T15:53:52.945597Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.945599Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.945600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.945696Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.945704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:52.945707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::3
2023-01-23T15:53:52.945709Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.945712Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.945714Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.945806Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.945812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:52.945814Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::4
2023-01-23T15:53:52.945816Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.945819Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.945820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.945907Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.945915Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:52.945917Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::5
2023-01-23T15:53:52.945919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.945922Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.945923Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.946017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T15:53:52.946020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::6
2023-01-23T15:53:52.946022Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946024Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.946120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T15:53:52.946122Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::7
2023-01-23T15:53:52.946124Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946127Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946128Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946217Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.946224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T15:53:52.946226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::8
2023-01-23T15:53:52.946228Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946231Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946320Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.946326Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-23T15:53:52.946328Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::9
2023-01-23T15:53:52.946330Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946333Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946423Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594184,
    events_root: None,
}
2023-01-23T15:53:52.946429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-23T15:53:52.946431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::10
2023-01-23T15:53:52.946433Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946436Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946527Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.946533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-23T15:53:52.946535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::11
2023-01-23T15:53:52.946537Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946540Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946541Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946629Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.946635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-23T15:53:52.946637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::12
2023-01-23T15:53:52.946639Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946642Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.946743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-23T15:53:52.946745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::13
2023-01-23T15:53:52.946747Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946749Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946838Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594288,
    events_root: None,
}
2023-01-23T15:53:52.946844Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-23T15:53:52.946847Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::14
2023-01-23T15:53:52.946848Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946851Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.946940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.946946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-23T15:53:52.946949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::15
2023-01-23T15:53:52.946951Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.946954Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.946955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947043Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.947050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-23T15:53:52.947052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::16
2023-01-23T15:53:52.947054Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.947056Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.947058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.947153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-23T15:53:52.947155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::17
2023-01-23T15:53:52.947157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.947160Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.947161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947250Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.947257Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-23T15:53:52.947259Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::18
2023-01-23T15:53:52.947261Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.947263Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.947265Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947353Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.947359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-23T15:53:52.947361Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::19
2023-01-23T15:53:52.947363Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.947365Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.947367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947455Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.947461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-23T15:53:52.947464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::20
2023-01-23T15:53:52.947466Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.947469Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.947470Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947559Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.947566Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-23T15:53:52.947569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::21
2023-01-23T15:53:52.947570Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.947573Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.947574Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947665Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.947671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-23T15:53:52.947673Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::22
2023-01-23T15:53:52.947675Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.947678Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.947680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947779Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.947786Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-23T15:53:52.947788Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::23
2023-01-23T15:53:52.947790Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.947792Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.947794Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947887Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594184,
    events_root: None,
}
2023-01-23T15:53:52.947894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 24
2023-01-23T15:53:52.947896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::24
2023-01-23T15:53:52.947898Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.947901Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.947902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.947991Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.947997Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 25
2023-01-23T15:53:52.948000Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::25
2023-01-23T15:53:52.948001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948004Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.948005Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.948093Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.948099Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 26
2023-01-23T15:53:52.948101Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::26
2023-01-23T15:53:52.948103Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948105Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.948106Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.948196Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.948202Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 27
2023-01-23T15:53:52.948204Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::27
2023-01-23T15:53:52.948206Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948209Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.948210Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.948299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594276,
    events_root: None,
}
2023-01-23T15:53:52.948305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 28
2023-01-23T15:53:52.948307Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::28
2023-01-23T15:53:52.948309Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948311Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.948313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.948400Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.948406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 29
2023-01-23T15:53:52.948408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::29
2023-01-23T15:53:52.948410Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948412Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.948414Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.948502Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.948508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 30
2023-01-23T15:53:52.948510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::30
2023-01-23T15:53:52.948512Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948515Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.948516Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.948604Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.948610Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 31
2023-01-23T15:53:52.948612Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::31
2023-01-23T15:53:52.948614Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948616Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.948618Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.948711Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.948717Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 32
2023-01-23T15:53:52.948719Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::32
2023-01-23T15:53:52.948722Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948724Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.948725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.948813Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.948820Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 33
2023-01-23T15:53:52.948822Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::33
2023-01-23T15:53:52.948824Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948826Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.948827Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.948915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.948921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 34
2023-01-23T15:53:52.948924Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::34
2023-01-23T15:53:52.948925Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.948928Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.948929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 35
2023-01-23T15:53:52.949024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::35
2023-01-23T15:53:52.949027Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949030Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949118Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949125Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 36
2023-01-23T15:53:52.949127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::36
2023-01-23T15:53:52.949129Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949131Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949133Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949227Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 37
2023-01-23T15:53:52.949229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::37
2023-01-23T15:53:52.949231Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949234Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949236Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949323Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949329Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 38
2023-01-23T15:53:52.949332Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::38
2023-01-23T15:53:52.949334Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949337Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949425Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 39
2023-01-23T15:53:52.949434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::39
2023-01-23T15:53:52.949436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949438Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949527Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 40
2023-01-23T15:53:52.949535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::40
2023-01-23T15:53:52.949537Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949539Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949541Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949640Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 41
2023-01-23T15:53:52.949642Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::41
2023-01-23T15:53:52.949644Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949646Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949738Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949744Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 42
2023-01-23T15:53:52.949746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::42
2023-01-23T15:53:52.949748Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949751Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949752Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949840Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 43
2023-01-23T15:53:52.949848Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::43
2023-01-23T15:53:52.949850Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949852Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.949943Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.949949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 44
2023-01-23T15:53:52.949951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::44
2023-01-23T15:53:52.949953Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.949955Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.949957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950044Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 45
2023-01-23T15:53:52.950052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::45
2023-01-23T15:53:52.950054Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950057Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950146Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 46
2023-01-23T15:53:52.950154Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::46
2023-01-23T15:53:52.950156Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950159Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950249Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950255Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 47
2023-01-23T15:53:52.950257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::47
2023-01-23T15:53:52.950259Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950262Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950350Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950356Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 48
2023-01-23T15:53:52.950359Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::48
2023-01-23T15:53:52.950360Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950363Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950452Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950458Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 49
2023-01-23T15:53:52.950460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::49
2023-01-23T15:53:52.950462Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950465Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950561Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 50
2023-01-23T15:53:52.950563Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::50
2023-01-23T15:53:52.950565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950567Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950569Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950657Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950663Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 51
2023-01-23T15:53:52.950665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::51
2023-01-23T15:53:52.950667Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950669Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950758Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 52
2023-01-23T15:53:52.950766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::52
2023-01-23T15:53:52.950768Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950771Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950772Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950860Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950866Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 53
2023-01-23T15:53:52.950868Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::53
2023-01-23T15:53:52.950870Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950873Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950874Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.950961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.950967Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 54
2023-01-23T15:53:52.950969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::54
2023-01-23T15:53:52.950971Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.950974Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.950975Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.951063Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.951070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 55
2023-01-23T15:53:52.951072Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::55
2023-01-23T15:53:52.951074Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.951078Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.951079Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.951167Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.951173Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 56
2023-01-23T15:53:52.951175Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::56
2023-01-23T15:53:52.951177Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.951179Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.951181Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.951268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.951274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 57
2023-01-23T15:53:52.951276Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::57
2023-01-23T15:53:52.951278Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.951280Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.951282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.951370Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.951376Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 58
2023-01-23T15:53:52.951378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::58
2023-01-23T15:53:52.951380Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.951383Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.951384Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.951486Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.951495Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 59
2023-01-23T15:53:52.951498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::59
2023-01-23T15:53:52.951500Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.951503Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.951505Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.951621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.951629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 60
2023-01-23T15:53:52.951632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::60
2023-01-23T15:53:52.951635Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.951638Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.951639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.951762Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.951771Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 61
2023-01-23T15:53:52.951776Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::61
2023-01-23T15:53:52.951778Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.951782Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.951784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.951914Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.951923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 62
2023-01-23T15:53:52.951927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::62
2023-01-23T15:53:52.951930Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.951933Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.951935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.952059Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.952068Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 63
2023-01-23T15:53:52.952071Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::63
2023-01-23T15:53:52.952073Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.952076Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.952079Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.952197Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.952207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 64
2023-01-23T15:53:52.952210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::64
2023-01-23T15:53:52.952214Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.952217Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.952219Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.952346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.952355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 65
2023-01-23T15:53:52.952358Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::65
2023-01-23T15:53:52.952361Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.952364Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.952366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.952494Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.952503Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 66
2023-01-23T15:53:52.952508Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::66
2023-01-23T15:53:52.952511Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.952514Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.952516Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.952643Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.952653Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 67
2023-01-23T15:53:52.952656Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::67
2023-01-23T15:53:52.952658Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.952661Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.952663Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.952801Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.952811Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 68
2023-01-23T15:53:52.952814Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::68
2023-01-23T15:53:52.952816Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.952818Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.952820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.952918Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.952924Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 69
2023-01-23T15:53:52.952927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::69
2023-01-23T15:53:52.952928Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.952931Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.952933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953021Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953028Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 70
2023-01-23T15:53:52.953030Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::70
2023-01-23T15:53:52.953032Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953034Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953036Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 71
2023-01-23T15:53:52.953133Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::71
2023-01-23T15:53:52.953135Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953138Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953139Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953227Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 72
2023-01-23T15:53:52.953236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::72
2023-01-23T15:53:52.953239Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953242Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953243Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953332Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953339Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 73
2023-01-23T15:53:52.953341Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::73
2023-01-23T15:53:52.953343Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953346Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953347Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953435Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953442Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 74
2023-01-23T15:53:52.953444Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::74
2023-01-23T15:53:52.953446Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953449Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953450Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953538Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 75
2023-01-23T15:53:52.953548Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::75
2023-01-23T15:53:52.953550Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953552Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953553Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953649Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953658Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 76
2023-01-23T15:53:52.953661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::76
2023-01-23T15:53:52.953663Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953666Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953668Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953759Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953765Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 77
2023-01-23T15:53:52.953768Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::77
2023-01-23T15:53:52.953769Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953772Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953861Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 78
2023-01-23T15:53:52.953870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::78
2023-01-23T15:53:52.953871Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953874Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953875Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.953963Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.953969Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 79
2023-01-23T15:53:52.953973Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::79
2023-01-23T15:53:52.953975Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.953977Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.953979Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954067Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.954073Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 80
2023-01-23T15:53:52.954075Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::80
2023-01-23T15:53:52.954077Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.954080Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.954082Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954171Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.954177Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 81
2023-01-23T15:53:52.954179Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::81
2023-01-23T15:53:52.954181Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.954184Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.954185Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954274Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.954281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 82
2023-01-23T15:53:52.954284Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::82
2023-01-23T15:53:52.954286Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.954288Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.954289Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.954383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 83
2023-01-23T15:53:52.954385Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::83
2023-01-23T15:53:52.954387Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.954390Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.954391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.954487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 84
2023-01-23T15:53:52.954489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::84
2023-01-23T15:53:52.954491Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.954494Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.954495Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954583Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.954589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 85
2023-01-23T15:53:52.954592Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::85
2023-01-23T15:53:52.954593Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.954596Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.954597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954688Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.954694Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 86
2023-01-23T15:53:52.954696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::86
2023-01-23T15:53:52.954698Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.954701Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.954703Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.954796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 87
2023-01-23T15:53:52.954799Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::87
2023-01-23T15:53:52.954801Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.954803Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.954804Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.954899Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 88
2023-01-23T15:53:52.954902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::88
2023-01-23T15:53:52.954903Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.954906Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.954907Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.954995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955001Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 89
2023-01-23T15:53:52.955003Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::89
2023-01-23T15:53:52.955005Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955008Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.955010Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.955097Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955104Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 90
2023-01-23T15:53:52.955106Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::90
2023-01-23T15:53:52.955108Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955110Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.955111Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.955200Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 91
2023-01-23T15:53:52.955208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::91
2023-01-23T15:53:52.955209Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955212Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.955213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.955300Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 92
2023-01-23T15:53:52.955309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::92
2023-01-23T15:53:52.955310Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955314Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.955315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.955402Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 93
2023-01-23T15:53:52.955411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::93
2023-01-23T15:53:52.955413Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955415Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.955417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.955506Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955512Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 94
2023-01-23T15:53:52.955514Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::94
2023-01-23T15:53:52.955516Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955518Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.955520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.955607Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955613Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 95
2023-01-23T15:53:52.955615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::95
2023-01-23T15:53:52.955617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955620Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.955622Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.955711Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 96
2023-01-23T15:53:52.955721Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::96
2023-01-23T15:53:52.955724Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955727Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.955729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.955836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 97
2023-01-23T15:53:52.955845Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::London::97
2023-01-23T15:53:52.955846Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955849Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.955850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.955939Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.955946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:52.955948Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::0
2023-01-23T15:53:52.955950Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.955952Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.955953Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956043Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.956050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:52.956053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::1
2023-01-23T15:53:52.956055Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956057Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.956153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:52.956155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::2
2023-01-23T15:53:52.956157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956159Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956250Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.956256Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:52.956258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::3
2023-01-23T15:53:52.956260Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956263Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956265Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956354Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.956361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:52.956363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::4
2023-01-23T15:53:52.956364Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956367Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956457Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.956463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:52.956466Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::5
2023-01-23T15:53:52.956467Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956470Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.956567Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T15:53:52.956570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::6
2023-01-23T15:53:52.956572Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956574Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956575Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956665Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.956671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T15:53:52.956674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::7
2023-01-23T15:53:52.956675Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956678Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956679Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956767Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.956773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T15:53:52.956775Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::8
2023-01-23T15:53:52.956779Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956782Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956783Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956871Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.956878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-23T15:53:52.956880Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::9
2023-01-23T15:53:52.956882Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956885Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.956975Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594184,
    events_root: None,
}
2023-01-23T15:53:52.956981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-23T15:53:52.956984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::10
2023-01-23T15:53:52.956986Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.956988Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.956990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.957078Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.957085Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-23T15:53:52.957087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::11
2023-01-23T15:53:52.957089Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.957091Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.957093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.957181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.957187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-23T15:53:52.957189Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::12
2023-01-23T15:53:52.957191Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.957193Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.957195Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.957285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594220,
    events_root: None,
}
2023-01-23T15:53:52.957291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-23T15:53:52.957293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::13
2023-01-23T15:53:52.957295Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.957297Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.957298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.957387Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594288,
    events_root: None,
}
2023-01-23T15:53:52.957394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-23T15:53:52.957396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::14
2023-01-23T15:53:52.957398Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.957401Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.957402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.957491Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.957497Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-23T15:53:52.957499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::15
2023-01-23T15:53:52.957501Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.957503Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.957505Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.957594Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.957600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-23T15:53:52.957602Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::16
2023-01-23T15:53:52.957605Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.957607Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.957609Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.957705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.957711Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-23T15:53:52.957714Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::17
2023-01-23T15:53:52.957716Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.957718Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.957719Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.957808Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.957815Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-23T15:53:52.957818Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::18
2023-01-23T15:53:52.957820Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.957822Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.957824Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.957912Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.957918Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-23T15:53:52.957920Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::19
2023-01-23T15:53:52.957922Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.957925Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.957927Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958015Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.958021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-23T15:53:52.958024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::20
2023-01-23T15:53:52.958026Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958028Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.958029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958117Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594116,
    events_root: None,
}
2023-01-23T15:53:52.958125Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-23T15:53:52.958127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::21
2023-01-23T15:53:52.958129Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958131Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.958133Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.958227Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-23T15:53:52.958230Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::22
2023-01-23T15:53:52.958231Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958234Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.958235Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.958330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-23T15:53:52.958332Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::23
2023-01-23T15:53:52.958334Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958337Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.958339Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958427Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594184,
    events_root: None,
}
2023-01-23T15:53:52.958433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-23T15:53:52.958436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::24
2023-01-23T15:53:52.958437Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958440Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.958441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958530Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.958536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-23T15:53:52.958538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::25
2023-01-23T15:53:52.958540Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958542Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.958544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.958639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-23T15:53:52.958641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::26
2023-01-23T15:53:52.958644Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958646Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.958647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958739Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594208,
    events_root: None,
}
2023-01-23T15:53:52.958745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-23T15:53:52.958747Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::27
2023-01-23T15:53:52.958749Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958751Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-23T15:53:52.958752Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958840Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1594276,
    events_root: None,
}
2023-01-23T15:53:52.958846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-23T15:53:52.958848Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::28
2023-01-23T15:53:52.958850Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958854Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.958855Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.958941Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.958948Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-23T15:53:52.958950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::29
2023-01-23T15:53:52.958952Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.958955Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.958956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959044Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-23T15:53:52.959053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::30
2023-01-23T15:53:52.959054Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.959057Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.959058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-23T15:53:52.959155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::31
2023-01-23T15:53:52.959157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.959160Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.959161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959249Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959256Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-23T15:53:52.959258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::32
2023-01-23T15:53:52.959260Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.959263Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.959264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959352Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959358Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-23T15:53:52.959361Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::33
2023-01-23T15:53:52.959363Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.959365Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.959366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959459Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-23T15:53:52.959461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::34
2023-01-23T15:53:52.959464Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.959466Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.959468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959554Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959561Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-23T15:53:52.959563Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::35
2023-01-23T15:53:52.959565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.959567Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.959568Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959656Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959662Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 36
2023-01-23T15:53:52.959665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::36
2023-01-23T15:53:52.959666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.959669Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.959670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 37
2023-01-23T15:53:52.959782Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::37
2023-01-23T15:53:52.959784Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.959786Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.959788Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959883Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959891Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 38
2023-01-23T15:53:52.959893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::38
2023-01-23T15:53:52.959895Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.959898Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.959899Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.959987Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.959993Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 39
2023-01-23T15:53:52.959995Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::39
2023-01-23T15:53:52.959997Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960000Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.960090Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.960096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 40
2023-01-23T15:53:52.960098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::40
2023-01-23T15:53:52.960100Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960102Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.960192Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.960200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 41
2023-01-23T15:53:52.960202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::41
2023-01-23T15:53:52.960204Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960206Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960207Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.960296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.960302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 42
2023-01-23T15:53:52.960304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::42
2023-01-23T15:53:52.960306Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960309Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960310Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.960398Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.960405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 43
2023-01-23T15:53:52.960407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::43
2023-01-23T15:53:52.960409Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960411Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960413Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.960502Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.960508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 44
2023-01-23T15:53:52.960510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::44
2023-01-23T15:53:52.960512Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960515Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960516Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.960605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.960611Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 45
2023-01-23T15:53:52.960613Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::45
2023-01-23T15:53:52.960615Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960618Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960620Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.960709Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.960715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 46
2023-01-23T15:53:52.960717Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::46
2023-01-23T15:53:52.960720Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960722Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960724Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.960811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.960817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 47
2023-01-23T15:53:52.960819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::47
2023-01-23T15:53:52.960821Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960824Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960825Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.960913Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.960919Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 48
2023-01-23T15:53:52.960922Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::48
2023-01-23T15:53:52.960923Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.960926Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.960927Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 49
2023-01-23T15:53:52.961025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::49
2023-01-23T15:53:52.961026Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961029Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961119Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961125Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 50
2023-01-23T15:53:52.961127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::50
2023-01-23T15:53:52.961129Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961132Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961133Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961220Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 51
2023-01-23T15:53:52.961229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::51
2023-01-23T15:53:52.961230Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961234Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961235Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961323Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 52
2023-01-23T15:53:52.961332Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::52
2023-01-23T15:53:52.961334Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961336Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961337Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 53
2023-01-23T15:53:52.961435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::53
2023-01-23T15:53:52.961437Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961439Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961535Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 54
2023-01-23T15:53:52.961537Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::54
2023-01-23T15:53:52.961540Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961543Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961637Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961643Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 55
2023-01-23T15:53:52.961645Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::55
2023-01-23T15:53:52.961647Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961650Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961651Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961748Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 56
2023-01-23T15:53:52.961750Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::56
2023-01-23T15:53:52.961752Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961755Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961846Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 57
2023-01-23T15:53:52.961854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::57
2023-01-23T15:53:52.961856Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961859Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961860Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.961948Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.961954Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 58
2023-01-23T15:53:52.961956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::58
2023-01-23T15:53:52.961958Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.961961Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.961962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962051Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 59
2023-01-23T15:53:52.962059Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::59
2023-01-23T15:53:52.962062Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962065Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962161Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 60
2023-01-23T15:53:52.962163Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::60
2023-01-23T15:53:52.962165Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962167Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962257Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 61
2023-01-23T15:53:52.962265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::61
2023-01-23T15:53:52.962267Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962270Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962272Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962361Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962368Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 62
2023-01-23T15:53:52.962370Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::62
2023-01-23T15:53:52.962372Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962374Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962375Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 63
2023-01-23T15:53:52.962472Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::63
2023-01-23T15:53:52.962474Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962477Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962566Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 64
2023-01-23T15:53:52.962575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::64
2023-01-23T15:53:52.962578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962580Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 65
2023-01-23T15:53:52.962678Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::65
2023-01-23T15:53:52.962680Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962683Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962772Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 66
2023-01-23T15:53:52.962780Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::66
2023-01-23T15:53:52.962782Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962784Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962785Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 67
2023-01-23T15:53:52.962883Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::67
2023-01-23T15:53:52.962885Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962887Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962889Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.962978Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.962984Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 68
2023-01-23T15:53:52.962986Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::68
2023-01-23T15:53:52.962988Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.962990Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.962991Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.963080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.963086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 69
2023-01-23T15:53:52.963088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::69
2023-01-23T15:53:52.963090Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.963093Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.963094Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.963181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.963188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 70
2023-01-23T15:53:52.963190Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::70
2023-01-23T15:53:52.963192Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.963195Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.963196Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.963285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.963291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 71
2023-01-23T15:53:52.963293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::71
2023-01-23T15:53:52.963295Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.963297Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.963298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.963388Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.963394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 72
2023-01-23T15:53:52.963396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::72
2023-01-23T15:53:52.963398Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.963400Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.963402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.963489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.963496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 73
2023-01-23T15:53:52.963498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::73
2023-01-23T15:53:52.963500Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.963503Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.963504Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.963593Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.963599Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 74
2023-01-23T15:53:52.963601Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::74
2023-01-23T15:53:52.963603Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.963605Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.963606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.963694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.963701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 75
2023-01-23T15:53:52.963703Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::75
2023-01-23T15:53:52.963705Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.963708Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.963710Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.963813Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.963822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 76
2023-01-23T15:53:52.963826Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::76
2023-01-23T15:53:52.963828Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.963831Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.963832Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.963931Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.963937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 77
2023-01-23T15:53:52.963940Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::77
2023-01-23T15:53:52.963941Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.963944Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.963945Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964033Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 78
2023-01-23T15:53:52.964043Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::78
2023-01-23T15:53:52.964045Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964047Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964049Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964137Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 79
2023-01-23T15:53:52.964146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::79
2023-01-23T15:53:52.964148Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964150Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964240Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964246Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 80
2023-01-23T15:53:52.964248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::80
2023-01-23T15:53:52.964250Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964252Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964348Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 81
2023-01-23T15:53:52.964351Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::81
2023-01-23T15:53:52.964353Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964355Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964356Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 82
2023-01-23T15:53:52.964452Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::82
2023-01-23T15:53:52.964454Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964456Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964547Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964553Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 83
2023-01-23T15:53:52.964555Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::83
2023-01-23T15:53:52.964557Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964560Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964649Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 84
2023-01-23T15:53:52.964659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::84
2023-01-23T15:53:52.964660Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964663Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964664Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 85
2023-01-23T15:53:52.964765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::85
2023-01-23T15:53:52.964767Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964769Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964860Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964866Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 86
2023-01-23T15:53:52.964868Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::86
2023-01-23T15:53:52.964870Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964873Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964874Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.964963Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.964969Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 87
2023-01-23T15:53:52.964971Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::87
2023-01-23T15:53:52.964973Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.964975Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.964977Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965065Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.965071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 88
2023-01-23T15:53:52.965074Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::88
2023-01-23T15:53:52.965075Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.965079Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.965080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965167Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.965174Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 89
2023-01-23T15:53:52.965176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::89
2023-01-23T15:53:52.965178Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.965181Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.965182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965270Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.965276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 90
2023-01-23T15:53:52.965278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::90
2023-01-23T15:53:52.965280Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.965283Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.965284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965371Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.965378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 91
2023-01-23T15:53:52.965380Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::91
2023-01-23T15:53:52.965382Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.965385Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.965386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965474Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.965481Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 92
2023-01-23T15:53:52.965483Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::92
2023-01-23T15:53:52.965485Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.965487Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.965489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965577Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.965583Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 93
2023-01-23T15:53:52.965585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::93
2023-01-23T15:53:52.965586Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.965589Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.965590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965685Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.965692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 94
2023-01-23T15:53:52.965694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::94
2023-01-23T15:53:52.965696Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.965699Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.965700Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965788Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.965794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 95
2023-01-23T15:53:52.965797Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::95
2023-01-23T15:53:52.965799Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.965801Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.965802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965890Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.965897Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 96
2023-01-23T15:53:52.965899Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::96
2023-01-23T15:53:52.965900Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.965903Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.965905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.965993Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.966000Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 97
2023-01-23T15:53:52.966002Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divByZero"::Merge::97
2023-01-23T15:53:52.966004Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.966007Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-23T15:53:52.966008Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:52.966096Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1596503,
    events_root: None,
}
2023-01-23T15:53:52.967550Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/divByZero.json"
2023-01-23T15:53:52.967582Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:52.993614Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:52.993727Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.993731Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:52.993785Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.993787Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:52.993844Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.993846Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:52.993898Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.993901Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:52.993947Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.993950Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:52.994012Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.994014Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:52.994071Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.994073Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:53:52.994117Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.994119Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T15:53:52.994162Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.994164Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T15:53:52.994216Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.994217Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T15:53:52.994265Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.994267Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-23T15:53:52.994314Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.994316Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-23T15:53:52.994358Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:52.994429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:52.994433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::3
2023-01-23T15:53:52.994436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:52.994439Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:52.994441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.359631Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3157330,
    events_root: None,
}
2023-01-23T15:53:53.359657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-23T15:53:53.359667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::7
2023-01-23T15:53:53.359669Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.359674Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.359676Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.359874Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3050449,
    events_root: None,
}
2023-01-23T15:53:53.359884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-23T15:53:53.359887Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::9
2023-01-23T15:53:53.359892Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.359895Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.359897Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.360084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3126125,
    events_root: None,
}
2023-01-23T15:53:53.360094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:53.360098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::0
2023-01-23T15:53:53.360102Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.360106Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.360108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.360331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3960826,
    events_root: None,
}
2023-01-23T15:53:53.360342Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:53.360345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::1
2023-01-23T15:53:53.360349Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.360353Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.360354Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.360584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5002895,
    events_root: None,
}
2023-01-23T15:53:53.360595Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:53.360598Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::2
2023-01-23T15:53:53.360601Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.360604Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.360606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.360807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4126305,
    events_root: None,
}
2023-01-23T15:53:53.360818Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:53.360821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::4
2023-01-23T15:53:53.360824Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.360827Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.360829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.361027Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955221,
    events_root: None,
}
2023-01-23T15:53:53.361039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:53.361042Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::5
2023-01-23T15:53:53.361045Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.361048Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.361050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.361250Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3960523,
    events_root: None,
}
2023-01-23T15:53:53.361261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-23T15:53:53.361264Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::6
2023-01-23T15:53:53.361268Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.361272Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.361274Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.361471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3975240,
    events_root: None,
}
2023-01-23T15:53:53.361482Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-23T15:53:53.361485Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::8
2023-01-23T15:53:53.361488Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.361491Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.361494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.361699Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954982,
    events_root: None,
}
2023-01-23T15:53:53.361711Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-23T15:53:53.361714Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Istanbul::10
2023-01-23T15:53:53.361717Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.361720Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.361722Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.361919Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3972701,
    events_root: None,
}
2023-01-23T15:53:53.361931Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:53.361934Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::3
2023-01-23T15:53:53.361937Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.361941Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.361943Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.362129Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3157330,
    events_root: None,
}
2023-01-23T15:53:53.362139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-23T15:53:53.362143Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::7
2023-01-23T15:53:53.362145Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.362148Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.362151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.362332Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3050449,
    events_root: None,
}
2023-01-23T15:53:53.362344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-23T15:53:53.362347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::9
2023-01-23T15:53:53.362350Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.362353Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.362355Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.362540Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3126125,
    events_root: None,
}
2023-01-23T15:53:53.362550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:53.362554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::0
2023-01-23T15:53:53.362556Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.362559Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.362561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.362752Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065239,
    events_root: None,
}
2023-01-23T15:53:53.362762Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:53.362765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::1
2023-01-23T15:53:53.362770Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.362774Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.362775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.362984Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4107672,
    events_root: None,
}
2023-01-23T15:53:53.362994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:53.362997Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::2
2023-01-23T15:53:53.362999Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.363002Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.363005Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.363193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3188095,
    events_root: None,
}
2023-01-23T15:53:53.363205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:53.363208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::4
2023-01-23T15:53:53.363211Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.363215Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.363217Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.363402Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059635,
    events_root: None,
}
2023-01-23T15:53:53.363412Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:53.363415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::5
2023-01-23T15:53:53.363418Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.363421Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.363423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.363609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063645,
    events_root: None,
}
2023-01-23T15:53:53.363619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-23T15:53:53.363624Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::6
2023-01-23T15:53:53.363627Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.363630Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.363632Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.363819Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3079654,
    events_root: None,
}
2023-01-23T15:53:53.363829Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-23T15:53:53.363832Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::8
2023-01-23T15:53:53.363836Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.363839Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.363841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.364027Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059395,
    events_root: None,
}
2023-01-23T15:53:53.364037Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-23T15:53:53.364040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Berlin::10
2023-01-23T15:53:53.364043Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.364046Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.364048Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.364237Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3075822,
    events_root: None,
}
2023-01-23T15:53:53.364247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:53.364251Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::3
2023-01-23T15:53:53.364253Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.364256Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.364259Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.364456Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3157330,
    events_root: None,
}
2023-01-23T15:53:53.364467Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T15:53:53.364470Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::7
2023-01-23T15:53:53.364472Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.364476Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.364479Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.364662Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3050449,
    events_root: None,
}
2023-01-23T15:53:53.364672Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-23T15:53:53.364675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::9
2023-01-23T15:53:53.364678Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.364681Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.364683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.364872Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3126125,
    events_root: None,
}
2023-01-23T15:53:53.364883Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:53.364886Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::0
2023-01-23T15:53:53.364889Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.364893Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.364895Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.365082Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065239,
    events_root: None,
}
2023-01-23T15:53:53.365093Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:53.365097Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::1
2023-01-23T15:53:53.365099Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.365103Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.365105Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.365315Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4107672,
    events_root: None,
}
2023-01-23T15:53:53.365325Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:53.365328Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::2
2023-01-23T15:53:53.365333Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.365336Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.365338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.365527Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3188095,
    events_root: None,
}
2023-01-23T15:53:53.365537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:53.365540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::4
2023-01-23T15:53:53.365543Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.365546Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.365548Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.365741Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059635,
    events_root: None,
}
2023-01-23T15:53:53.365751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:53.365754Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::5
2023-01-23T15:53:53.365759Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.365763Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.365765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.365951Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063645,
    events_root: None,
}
2023-01-23T15:53:53.365961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T15:53:53.365964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::6
2023-01-23T15:53:53.365968Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.365971Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.365973Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.366159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3079654,
    events_root: None,
}
2023-01-23T15:53:53.366169Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T15:53:53.366172Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::8
2023-01-23T15:53:53.366176Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.366179Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.366181Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.366364Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059395,
    events_root: None,
}
2023-01-23T15:53:53.366375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-23T15:53:53.366379Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::London::10
2023-01-23T15:53:53.366382Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.366386Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.366388Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.366578Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3075822,
    events_root: None,
}
2023-01-23T15:53:53.366588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:53.366591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::3
2023-01-23T15:53:53.366594Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.366598Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.366600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.366785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3157330,
    events_root: None,
}
2023-01-23T15:53:53.366795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T15:53:53.366800Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::7
2023-01-23T15:53:53.366802Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.366806Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.366808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.366990Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3050449,
    events_root: None,
}
2023-01-23T15:53:53.367000Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-23T15:53:53.367003Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::9
2023-01-23T15:53:53.367006Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.367009Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.367011Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.367195Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3126125,
    events_root: None,
}
2023-01-23T15:53:53.367205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:53.367208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::0
2023-01-23T15:53:53.367211Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.367214Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.367216Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.367400Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065239,
    events_root: None,
}
2023-01-23T15:53:53.367412Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:53.367415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::1
2023-01-23T15:53:53.367418Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.367421Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.367423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.367630Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4107672,
    events_root: None,
}
2023-01-23T15:53:53.367640Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:53.367643Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::2
2023-01-23T15:53:53.367646Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.367649Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.367653Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.367841Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3188095,
    events_root: None,
}
2023-01-23T15:53:53.367851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:53.367854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::4
2023-01-23T15:53:53.367857Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.367860Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.367862Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.368050Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059635,
    events_root: None,
}
2023-01-23T15:53:53.368061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:53.368064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::5
2023-01-23T15:53:53.368067Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.368071Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.368073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.368258Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063645,
    events_root: None,
}
2023-01-23T15:53:53.368270Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T15:53:53.368273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::6
2023-01-23T15:53:53.368275Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.368278Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.368280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.368473Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3079654,
    events_root: None,
}
2023-01-23T15:53:53.368484Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T15:53:53.368488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::8
2023-01-23T15:53:53.368491Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.368495Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.368497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.368681Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059395,
    events_root: None,
}
2023-01-23T15:53:53.368692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-23T15:53:53.368696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "exp"::Merge::10
2023-01-23T15:53:53.368698Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.368701Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.368704Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.368889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3075822,
    events_root: None,
}
2023-01-23T15:53:53.370523Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/exp.json"
2023-01-23T15:53:53.370552Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower2.json"
2023-01-23T15:53:53.396266Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:53.396376Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:53.396380Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:53.396440Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:53.396515Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:53.396521Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower2"::Istanbul::0
2023-01-23T15:53:53.396525Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower2.json"
2023-01-23T15:53:53.396530Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.396532Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.737742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10343082,
    events_root: None,
}
2023-01-23T15:53:53.737762Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:53.737768Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower2"::Berlin::0
2023-01-23T15:53:53.737771Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower2.json"
2023-01-23T15:53:53.737774Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.737775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.738094Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7165115,
    events_root: None,
}
2023-01-23T15:53:53.738102Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:53.738104Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower2"::London::0
2023-01-23T15:53:53.738106Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower2.json"
2023-01-23T15:53:53.738109Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.738110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.738426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7165115,
    events_root: None,
}
2023-01-23T15:53:53.738434Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:53.738437Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower2"::Merge::0
2023-01-23T15:53:53.738440Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower2.json"
2023-01-23T15:53:53.738442Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.738443Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:53.738734Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7165115,
    events_root: None,
}
2023-01-23T15:53:53.740101Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower2.json"
2023-01-23T15:53:53.740124Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256.json"
2023-01-23T15:53:53.764871Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:53.764971Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:53.764974Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:53.765032Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:53.765102Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:53.765106Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower256"::Istanbul::0
2023-01-23T15:53:53.765109Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256.json"
2023-01-23T15:53:53.765111Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:53.765113Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.118568Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 36029343,
    events_root: None,
}
2023-01-23T15:53:54.118608Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:54.118617Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower256"::Berlin::0
2023-01-23T15:53:54.118622Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256.json"
2023-01-23T15:53:54.118626Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:54.118628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.119621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24207574,
    events_root: None,
}
2023-01-23T15:53:54.119641Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:54.119644Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower256"::London::0
2023-01-23T15:53:54.119646Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256.json"
2023-01-23T15:53:54.119648Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:54.119649Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.120634Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24207574,
    events_root: None,
}
2023-01-23T15:53:54.120652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:54.120655Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower256"::Merge::0
2023-01-23T15:53:54.120657Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256.json"
2023-01-23T15:53:54.120659Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:54.120662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.121603Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24207574,
    events_root: None,
}
2023-01-23T15:53:54.123005Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256.json"
2023-01-23T15:53:54.123029Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256Of256.json"
2023-01-23T15:53:54.148348Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:54.148460Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.148465Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:54.148554Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.148646Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:54.148652Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower256Of256"::Istanbul::0
2023-01-23T15:53:54.148656Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256Of256.json"
2023-01-23T15:53:54.148660Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:54.148662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.548401Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 179368908,
    events_root: None,
}
2023-01-23T15:53:54.548439Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:54.548445Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower256Of256"::Berlin::0
2023-01-23T15:53:54.548448Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256Of256.json"
2023-01-23T15:53:54.548451Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:54.548453Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.552978Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 154164586,
    events_root: None,
}
2023-01-23T15:53:54.553012Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:54.553016Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower256Of256"::London::0
2023-01-23T15:53:54.553018Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256Of256.json"
2023-01-23T15:53:54.553021Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:54.553023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.557526Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 154164586,
    events_root: None,
}
2023-01-23T15:53:54.557553Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:54.557556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expPower256Of256"::Merge::0
2023-01-23T15:53:54.557559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256Of256.json"
2023-01-23T15:53:54.557561Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:54.557563Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.562016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 154164586,
    events_root: None,
}
2023-01-23T15:53:54.563224Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/expPower256Of256.json"
2023-01-23T15:53:54.563249Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/fib.json"
2023-01-23T15:53:54.587996Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:54.588098Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.588101Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:54.588155Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.588225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:54.588230Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "fib"::Istanbul::0
2023-01-23T15:53:54.588232Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/fib.json"
2023-01-23T15:53:54.588235Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:54.588237Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.958883Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666647,
    events_root: None,
}
2023-01-23T15:53:54.958906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:54.958911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "fib"::Berlin::0
2023-01-23T15:53:54.958914Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/fib.json"
2023-01-23T15:53:54.958917Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:54.958918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.959054Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666647,
    events_root: None,
}
2023-01-23T15:53:54.959061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:54.959063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "fib"::London::0
2023-01-23T15:53:54.959065Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/fib.json"
2023-01-23T15:53:54.959067Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:54.959068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.959158Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666647,
    events_root: None,
}
2023-01-23T15:53:54.959165Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:54.959167Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "fib"::Merge::0
2023-01-23T15:53:54.959169Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/fib.json"
2023-01-23T15:53:54.959171Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:54.959172Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:54.959262Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666647,
    events_root: None,
}
2023-01-23T15:53:54.960511Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/fib.json"
2023-01-23T15:53:54.960537Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:54.985570Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:54.985678Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.985682Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:54.985733Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.985735Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:54.985791Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.985793Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:54.985842Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.985844Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:54.985891Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.985893Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:54.985953Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.985954Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:54.986011Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.986013Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:53:54.986056Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:54.986126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:54.986131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Istanbul::0
2023-01-23T15:53:54.986134Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:54.986137Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:54.986138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.366281Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3957374,
    events_root: None,
}
2023-01-23T15:53:55.366305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:55.366312Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Istanbul::1
2023-01-23T15:53:55.366314Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.366317Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.366318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.366545Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3959972,
    events_root: None,
}
2023-01-23T15:53:55.366555Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:55.366557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Istanbul::2
2023-01-23T15:53:55.366559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.366562Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.366563Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.366741Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031349,
    events_root: None,
}
2023-01-23T15:53:55.366750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:55.366753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Istanbul::3
2023-01-23T15:53:55.366755Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.366757Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.366759Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.366932Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029427,
    events_root: None,
}
2023-01-23T15:53:55.366941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:55.366944Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Istanbul::4
2023-01-23T15:53:55.366946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.366949Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.366950Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.367137Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3959117,
    events_root: None,
}
2023-01-23T15:53:55.367149Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:55.367151Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Istanbul::5
2023-01-23T15:53:55.367153Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.367157Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.367158Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.367359Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3999974,
    events_root: None,
}
2023-01-23T15:53:55.367368Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:55.367371Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Berlin::0
2023-01-23T15:53:55.367372Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.367375Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.367376Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.367557Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061787,
    events_root: None,
}
2023-01-23T15:53:55.367567Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:55.367570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Berlin::1
2023-01-23T15:53:55.367572Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.367574Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.367576Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.367751Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064750,
    events_root: None,
}
2023-01-23T15:53:55.367760Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:55.367762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Berlin::2
2023-01-23T15:53:55.367764Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.367766Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.367768Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.367940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031349,
    events_root: None,
}
2023-01-23T15:53:55.367949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:55.367951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Berlin::3
2023-01-23T15:53:55.367953Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.367956Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.367957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.368129Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029427,
    events_root: None,
}
2023-01-23T15:53:55.368138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:55.368140Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Berlin::4
2023-01-23T15:53:55.368143Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.368146Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.368147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.368325Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063531,
    events_root: None,
}
2023-01-23T15:53:55.368334Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:55.368336Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Berlin::5
2023-01-23T15:53:55.368338Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.368340Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.368342Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.368517Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061720,
    events_root: None,
}
2023-01-23T15:53:55.368526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:55.368528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::London::0
2023-01-23T15:53:55.368530Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.368532Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.368534Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.368709Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061787,
    events_root: None,
}
2023-01-23T15:53:55.368718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:55.368721Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::London::1
2023-01-23T15:53:55.368723Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.368726Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.368728Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.368901Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064750,
    events_root: None,
}
2023-01-23T15:53:55.368911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:55.368914Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::London::2
2023-01-23T15:53:55.368916Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.368918Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.368920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.369093Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031349,
    events_root: None,
}
2023-01-23T15:53:55.369101Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:55.369104Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::London::3
2023-01-23T15:53:55.369106Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.369109Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.369110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.369282Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029427,
    events_root: None,
}
2023-01-23T15:53:55.369291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:55.369293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::London::4
2023-01-23T15:53:55.369295Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.369297Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.369299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.369472Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063531,
    events_root: None,
}
2023-01-23T15:53:55.369481Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:55.369484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::London::5
2023-01-23T15:53:55.369485Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.369488Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.369489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.369671Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061720,
    events_root: None,
}
2023-01-23T15:53:55.369680Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:55.369683Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Merge::0
2023-01-23T15:53:55.369684Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.369687Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.369688Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.369894Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061787,
    events_root: None,
}
2023-01-23T15:53:55.369904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:55.369906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Merge::1
2023-01-23T15:53:55.369908Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.369911Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.369912Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.370088Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064750,
    events_root: None,
}
2023-01-23T15:53:55.370096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:55.370099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Merge::2
2023-01-23T15:53:55.370101Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.370103Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.370105Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.370278Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031349,
    events_root: None,
}
2023-01-23T15:53:55.370288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:55.370291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Merge::3
2023-01-23T15:53:55.370293Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.370296Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.370297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.370474Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029427,
    events_root: None,
}
2023-01-23T15:53:55.370483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:55.370485Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Merge::4
2023-01-23T15:53:55.370487Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.370489Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.370491Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.370666Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063531,
    events_root: None,
}
2023-01-23T15:53:55.370675Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:55.370679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mod"::Merge::5
2023-01-23T15:53:55.370680Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.370683Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.370684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.370858Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061720,
    events_root: None,
}
2023-01-23T15:53:55.372196Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mod.json"
2023-01-23T15:53:55.372228Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.397728Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:55.397837Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.397841Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:55.397902Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.397906Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:55.397988Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.397992Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:55.398051Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.398054Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:55.398110Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.398113Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:55.398193Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.398197Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:55.398278Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.398282Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:53:55.398343Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.398347Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T15:53:55.398404Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.398408Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T15:53:55.398468Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.398470Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T15:53:55.398516Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.398589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:55.398594Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Istanbul::2
2023-01-23T15:53:55.398596Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.398599Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.398601Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.741553Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031731,
    events_root: None,
}
2023-01-23T15:53:55.741578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:55.741584Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Istanbul::5
2023-01-23T15:53:55.741587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.741590Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.741591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.741784Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034420,
    events_root: None,
}
2023-01-23T15:53:55.741793Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-23T15:53:55.741795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Istanbul::8
2023-01-23T15:53:55.741797Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.741800Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.741801Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.741993Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058745,
    events_root: None,
}
2023-01-23T15:53:55.742002Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:55.742005Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Istanbul::0
2023-01-23T15:53:55.742007Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.742009Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.742010Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.742203Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3956522,
    events_root: None,
}
2023-01-23T15:53:55.742212Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:55.742214Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Istanbul::1
2023-01-23T15:53:55.742216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.742218Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.742220Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.742404Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3959211,
    events_root: None,
}
2023-01-23T15:53:55.742414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:55.742417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Istanbul::3
2023-01-23T15:53:55.742419Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.742421Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.742423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.742607Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3956522,
    events_root: None,
}
2023-01-23T15:53:55.742616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:55.742618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Istanbul::4
2023-01-23T15:53:55.742620Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.742623Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.742624Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.742809Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003200,
    events_root: None,
}
2023-01-23T15:53:55.742819Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-23T15:53:55.742821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Istanbul::6
2023-01-23T15:53:55.742823Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.742826Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.742828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.743013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3959211,
    events_root: None,
}
2023-01-23T15:53:55.743023Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-23T15:53:55.743025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Istanbul::7
2023-01-23T15:53:55.743027Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.743030Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.743031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.743215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4006257,
    events_root: None,
}
2023-01-23T15:53:55.743224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:55.743227Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Berlin::2
2023-01-23T15:53:55.743229Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.743231Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.743232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.743400Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031731,
    events_root: None,
}
2023-01-23T15:53:55.743409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:55.743412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Berlin::5
2023-01-23T15:53:55.743414Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.743416Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.743417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.743583Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034420,
    events_root: None,
}
2023-01-23T15:53:55.743592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-23T15:53:55.743594Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Berlin::8
2023-01-23T15:53:55.743596Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.743599Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.743600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.743775Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058745,
    events_root: None,
}
2023-01-23T15:53:55.743783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:55.743786Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Berlin::0
2023-01-23T15:53:55.743788Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.743791Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.743792Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.743969Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060935,
    events_root: None,
}
2023-01-23T15:53:55.743978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:55.743980Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Berlin::1
2023-01-23T15:53:55.743982Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.743984Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.743986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.744155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063988,
    events_root: None,
}
2023-01-23T15:53:55.744164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:55.744166Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Berlin::3
2023-01-23T15:53:55.744168Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.744170Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.744171Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.744362Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060935,
    events_root: None,
}
2023-01-23T15:53:55.744373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:55.744376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Berlin::4
2023-01-23T15:53:55.744378Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.744380Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.744381Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.744561Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064465,
    events_root: None,
}
2023-01-23T15:53:55.744569Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-23T15:53:55.744572Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Berlin::6
2023-01-23T15:53:55.744574Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.744576Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.744578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.744750Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063988,
    events_root: None,
}
2023-01-23T15:53:55.744758Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-23T15:53:55.744761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Berlin::7
2023-01-23T15:53:55.744763Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.744765Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.744766Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.744935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067523,
    events_root: None,
}
2023-01-23T15:53:55.744944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:55.744946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::London::2
2023-01-23T15:53:55.744948Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.744951Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.744952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.745117Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031731,
    events_root: None,
}
2023-01-23T15:53:55.745126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:55.745128Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::London::5
2023-01-23T15:53:55.745130Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.745132Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.745134Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.745298Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034420,
    events_root: None,
}
2023-01-23T15:53:55.745307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T15:53:55.745309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::London::8
2023-01-23T15:53:55.745312Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.745314Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.745316Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.745488Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058745,
    events_root: None,
}
2023-01-23T15:53:55.745496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:55.745499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::London::0
2023-01-23T15:53:55.745501Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.745503Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.745505Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.745682Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060935,
    events_root: None,
}
2023-01-23T15:53:55.745691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:55.745693Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::London::1
2023-01-23T15:53:55.745695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.745698Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.745699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.745870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063988,
    events_root: None,
}
2023-01-23T15:53:55.745879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:55.745881Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::London::3
2023-01-23T15:53:55.745883Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.745886Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.745887Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.746056Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060935,
    events_root: None,
}
2023-01-23T15:53:55.746065Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:55.746067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::London::4
2023-01-23T15:53:55.746070Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.746072Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.746074Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.746252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064465,
    events_root: None,
}
2023-01-23T15:53:55.746261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T15:53:55.746263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::London::6
2023-01-23T15:53:55.746265Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.746268Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.746269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.746443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063988,
    events_root: None,
}
2023-01-23T15:53:55.746452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T15:53:55.746454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::London::7
2023-01-23T15:53:55.746456Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.746460Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.746461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.746632Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067523,
    events_root: None,
}
2023-01-23T15:53:55.746640Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:55.746643Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Merge::2
2023-01-23T15:53:55.746645Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.746647Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.746649Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.746814Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031731,
    events_root: None,
}
2023-01-23T15:53:55.746823Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:55.746825Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Merge::5
2023-01-23T15:53:55.746827Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.746829Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.746831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.746995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034420,
    events_root: None,
}
2023-01-23T15:53:55.747004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T15:53:55.747006Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Merge::8
2023-01-23T15:53:55.747009Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.747011Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.747013Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.747186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058745,
    events_root: None,
}
2023-01-23T15:53:55.747195Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:55.747197Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Merge::0
2023-01-23T15:53:55.747199Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.747202Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.747203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.747374Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060935,
    events_root: None,
}
2023-01-23T15:53:55.747383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:55.747385Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Merge::1
2023-01-23T15:53:55.747387Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.747390Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.747391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.747561Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063988,
    events_root: None,
}
2023-01-23T15:53:55.747569Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:55.747572Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Merge::3
2023-01-23T15:53:55.747574Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.747577Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.747578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.747749Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060935,
    events_root: None,
}
2023-01-23T15:53:55.747757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:55.747759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Merge::4
2023-01-23T15:53:55.747761Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.747763Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.747765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.747935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3064465,
    events_root: None,
}
2023-01-23T15:53:55.747944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T15:53:55.747946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Merge::6
2023-01-23T15:53:55.747948Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.747950Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.747952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.748121Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063988,
    events_root: None,
}
2023-01-23T15:53:55.748129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T15:53:55.748132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mul"::Merge::7
2023-01-23T15:53:55.748134Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.748136Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.748138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:55.748308Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067523,
    events_root: None,
}
2023-01-23T15:53:55.749691Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mul.json"
2023-01-23T15:53:55.749730Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:55.775226Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:55.775328Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775332Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:55.775383Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775385Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:55.775439Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775441Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:55.775492Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775495Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:55.775540Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775542Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:55.775601Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775603Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:55.775655Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775657Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:53:55.775700Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775702Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T15:53:55.775744Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775745Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T15:53:55.775797Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775799Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T15:53:55.775845Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775847Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-23T15:53:55.775896Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775898Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-23T15:53:55.775938Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775940Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-23T15:53:55.775984Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.775986Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-23T15:53:55.776040Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.776042Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-23T15:53:55.776090Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.776092Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-23T15:53:55.776133Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.776135Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-23T15:53:55.776185Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:55.776254Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:55.776258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::0
2023-01-23T15:53:55.776261Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:55.776264Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:55.776265Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.119554Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043424,
    events_root: None,
}
2023-01-23T15:53:56.119579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:56.119585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::1
2023-01-23T15:53:56.119588Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.119591Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.119592Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.119794Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059002,
    events_root: None,
}
2023-01-23T15:53:56.119803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-23T15:53:56.119805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::6
2023-01-23T15:53:56.119807Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.119810Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.119811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.119987Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3057171,
    events_root: None,
}
2023-01-23T15:53:56.119996Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-23T15:53:56.119998Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::9
2023-01-23T15:53:56.120000Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.120002Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.120004Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.120176Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063889,
    events_root: None,
}
2023-01-23T15:53:56.120185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-23T15:53:56.120187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::11
2023-01-23T15:53:56.120189Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.120192Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.120193Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.120362Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3041326,
    events_root: None,
}
2023-01-23T15:53:56.120370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-23T15:53:56.120372Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::12
2023-01-23T15:53:56.120374Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.120377Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.120378Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.120547Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.120555Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-23T15:53:56.120557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::13
2023-01-23T15:53:56.120559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.120561Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.120563Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.120736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.120747Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-23T15:53:56.120750Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::15
2023-01-23T15:53:56.120752Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.120756Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.120758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.120966Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.120975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:56.120978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::2
2023-01-23T15:53:56.120979Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.120982Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.120983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.121187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3980058,
    events_root: None,
}
2023-01-23T15:53:56.121198Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:56.121200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::3
2023-01-23T15:53:56.121202Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.121204Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.121206Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.121388Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3964474,
    events_root: None,
}
2023-01-23T15:53:56.121400Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:56.121402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::4
2023-01-23T15:53:56.121404Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.121406Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.121408Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.121590Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3968215,
    events_root: None,
}
2023-01-23T15:53:56.121601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:56.121604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::5
2023-01-23T15:53:56.121606Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.121608Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.121610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.121808Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3972225,
    events_root: None,
}
2023-01-23T15:53:56.121820Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-23T15:53:56.121823Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::7
2023-01-23T15:53:56.121824Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.121827Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.121828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.122013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3981168,
    events_root: None,
}
2023-01-23T15:53:56.122024Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-23T15:53:56.122026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::8
2023-01-23T15:53:56.122028Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.122030Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.122032Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.122228Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3976764,
    events_root: None,
}
2023-01-23T15:53:56.122242Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-23T15:53:56.122246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::10
2023-01-23T15:53:56.122249Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.122252Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.122253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.122448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3990983,
    events_root: None,
}
2023-01-23T15:53:56.122460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-23T15:53:56.122462Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Istanbul::14
2023-01-23T15:53:56.122464Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.122467Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.122468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.122648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3956986,
    events_root: None,
}
2023-01-23T15:53:56.122660Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:56.122662Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::0
2023-01-23T15:53:56.122664Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.122667Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.122668Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.122836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043424,
    events_root: None,
}
2023-01-23T15:53:56.122845Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:56.122847Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::1
2023-01-23T15:53:56.122849Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.122852Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.122853Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.123023Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059002,
    events_root: None,
}
2023-01-23T15:53:56.123032Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-23T15:53:56.123034Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::6
2023-01-23T15:53:56.123036Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.123038Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.123040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.123208Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3057171,
    events_root: None,
}
2023-01-23T15:53:56.123216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-23T15:53:56.123218Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::9
2023-01-23T15:53:56.123221Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.123223Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.123225Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.123394Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063889,
    events_root: None,
}
2023-01-23T15:53:56.123403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-23T15:53:56.123405Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::11
2023-01-23T15:53:56.123407Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.123410Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.123412Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.123633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3041326,
    events_root: None,
}
2023-01-23T15:53:56.123644Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-23T15:53:56.123647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::12
2023-01-23T15:53:56.123650Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.123653Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.123654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.123844Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.123854Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-23T15:53:56.123858Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::13
2023-01-23T15:53:56.123860Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.123864Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.123865Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.124070Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.124079Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-23T15:53:56.124082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::15
2023-01-23T15:53:56.124084Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.124086Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.124087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.124254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.124262Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:56.124265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::2
2023-01-23T15:53:56.124267Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.124269Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.124271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.124447Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3084835,
    events_root: None,
}
2023-01-23T15:53:56.124455Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:56.124458Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::3
2023-01-23T15:53:56.124460Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.124462Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.124464Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.124638Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3069251,
    events_root: None,
}
2023-01-23T15:53:56.124646Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:56.124648Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::4
2023-01-23T15:53:56.124650Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.124653Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.124654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.124825Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3072628,
    events_root: None,
}
2023-01-23T15:53:56.124833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:56.124835Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::5
2023-01-23T15:53:56.124838Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.124841Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.124842Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.125015Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3077003,
    events_root: None,
}
2023-01-23T15:53:56.125025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-23T15:53:56.125028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::7
2023-01-23T15:53:56.125030Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.125032Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.125033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.125206Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3085946,
    events_root: None,
}
2023-01-23T15:53:56.125214Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-23T15:53:56.125217Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::8
2023-01-23T15:53:56.125219Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.125221Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.125223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.125395Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3081542,
    events_root: None,
}
2023-01-23T15:53:56.125404Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-23T15:53:56.125406Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::10
2023-01-23T15:53:56.125408Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.125410Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.125412Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.125585Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3095761,
    events_root: None,
}
2023-01-23T15:53:56.125595Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-23T15:53:56.125598Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Berlin::14
2023-01-23T15:53:56.125600Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.125603Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.125604Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.125805Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061763,
    events_root: None,
}
2023-01-23T15:53:56.125814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:56.125817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::0
2023-01-23T15:53:56.125819Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.125821Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.125823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.125989Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043424,
    events_root: None,
}
2023-01-23T15:53:56.125997Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:56.126000Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::1
2023-01-23T15:53:56.126002Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.126004Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.126005Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.126175Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059002,
    events_root: None,
}
2023-01-23T15:53:56.126183Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T15:53:56.126186Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::6
2023-01-23T15:53:56.126188Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.126190Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.126192Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.126358Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3057171,
    events_root: None,
}
2023-01-23T15:53:56.126367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-23T15:53:56.126370Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::9
2023-01-23T15:53:56.126372Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.126374Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.126376Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.126546Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063889,
    events_root: None,
}
2023-01-23T15:53:56.126554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-23T15:53:56.126557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::11
2023-01-23T15:53:56.126559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.126561Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.126563Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.126736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3041326,
    events_root: None,
}
2023-01-23T15:53:56.126745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-23T15:53:56.126747Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::12
2023-01-23T15:53:56.126749Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.126751Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.126753Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.126920Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.126928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-23T15:53:56.126930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::13
2023-01-23T15:53:56.126932Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.126934Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.126936Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.127099Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.127108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-23T15:53:56.127110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::15
2023-01-23T15:53:56.127112Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.127114Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.127116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.127284Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.127294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:56.127297Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::2
2023-01-23T15:53:56.127300Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.127303Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.127305Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.127521Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3084835,
    events_root: None,
}
2023-01-23T15:53:56.127530Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:56.127533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::3
2023-01-23T15:53:56.127535Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.127538Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.127539Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.127716Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3069251,
    events_root: None,
}
2023-01-23T15:53:56.127724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:56.127726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::4
2023-01-23T15:53:56.127728Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.127731Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.127732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.127902Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3072628,
    events_root: None,
}
2023-01-23T15:53:56.127911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:56.127914Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::5
2023-01-23T15:53:56.127916Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.127918Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.127919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.128092Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3077003,
    events_root: None,
}
2023-01-23T15:53:56.128100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T15:53:56.128102Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::7
2023-01-23T15:53:56.128105Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.128107Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.128108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.128281Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3085946,
    events_root: None,
}
2023-01-23T15:53:56.128289Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T15:53:56.128292Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::8
2023-01-23T15:53:56.128294Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.128296Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.128298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.128470Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3081542,
    events_root: None,
}
2023-01-23T15:53:56.128478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-23T15:53:56.128481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::10
2023-01-23T15:53:56.128482Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.128485Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.128486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.128658Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3095761,
    events_root: None,
}
2023-01-23T15:53:56.128666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-23T15:53:56.128669Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::London::14
2023-01-23T15:53:56.128671Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.128673Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.128675Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.128846Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061763,
    events_root: None,
}
2023-01-23T15:53:56.128855Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:56.128857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::0
2023-01-23T15:53:56.128859Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.128862Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.128863Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.129030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3043424,
    events_root: None,
}
2023-01-23T15:53:56.129039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:56.129041Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::1
2023-01-23T15:53:56.129043Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.129046Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.129047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.129215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059002,
    events_root: None,
}
2023-01-23T15:53:56.129224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T15:53:56.129226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::6
2023-01-23T15:53:56.129228Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.129230Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.129233Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.129400Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3057171,
    events_root: None,
}
2023-01-23T15:53:56.129409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-23T15:53:56.129411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::9
2023-01-23T15:53:56.129413Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.129416Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.129417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.129586Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063889,
    events_root: None,
}
2023-01-23T15:53:56.129595Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-23T15:53:56.129597Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::11
2023-01-23T15:53:56.129599Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.129602Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.129603Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.129778Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3041326,
    events_root: None,
}
2023-01-23T15:53:56.129787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-23T15:53:56.129789Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::12
2023-01-23T15:53:56.129791Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.129794Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.129795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.129961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.129970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-23T15:53:56.129973Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::13
2023-01-23T15:53:56.129975Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.129977Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.129979Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.130166Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.130175Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-23T15:53:56.130177Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::15
2023-01-23T15:53:56.130180Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.130182Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.130183Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.130351Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030388,
    events_root: None,
}
2023-01-23T15:53:56.130360Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:56.130362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::2
2023-01-23T15:53:56.130364Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.130367Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.130368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.130538Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3084835,
    events_root: None,
}
2023-01-23T15:53:56.130547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:56.130549Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::3
2023-01-23T15:53:56.130551Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.130553Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.130555Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.130728Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3069251,
    events_root: None,
}
2023-01-23T15:53:56.130737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:56.130740Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::4
2023-01-23T15:53:56.130742Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.130745Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.130747Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.130924Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3072628,
    events_root: None,
}
2023-01-23T15:53:56.130932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:56.130935Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::5
2023-01-23T15:53:56.130937Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.130939Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.130941Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.131112Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3077003,
    events_root: None,
}
2023-01-23T15:53:56.131121Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T15:53:56.131123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::7
2023-01-23T15:53:56.131125Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.131128Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.131129Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.131301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3085946,
    events_root: None,
}
2023-01-23T15:53:56.131309Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T15:53:56.131311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::8
2023-01-23T15:53:56.131313Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.131316Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.131317Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.131492Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3081542,
    events_root: None,
}
2023-01-23T15:53:56.131501Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-23T15:53:56.131503Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::10
2023-01-23T15:53:56.131505Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.131508Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.131509Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.131684Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3095761,
    events_root: None,
}
2023-01-23T15:53:56.131693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-23T15:53:56.131695Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmod"::Merge::14
2023-01-23T15:53:56.131697Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.131700Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.131701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.131872Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061763,
    events_root: None,
}
2023-01-23T15:53:56.133555Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/mulmod.json"
2023-01-23T15:53:56.133582Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/not.json"
2023-01-23T15:53:56.160046Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:56.160149Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.160152Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:56.160206Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.160208Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:56.160265Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.160337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:56.160341Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Istanbul::0
2023-01-23T15:53:56.160343Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/not.json"
2023-01-23T15:53:56.160346Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.160348Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.535961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3997803,
    events_root: None,
}
2023-01-23T15:53:56.535989Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:56.535995Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Berlin::0
2023-01-23T15:53:56.535997Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/not.json"
2023-01-23T15:53:56.536000Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.536002Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.536186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059593,
    events_root: None,
}
2023-01-23T15:53:56.536195Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:56.536198Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::London::0
2023-01-23T15:53:56.536200Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/not.json"
2023-01-23T15:53:56.536202Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.536204Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.536374Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059593,
    events_root: None,
}
2023-01-23T15:53:56.536383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:56.536386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "not"::Merge::0
2023-01-23T15:53:56.536388Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/not.json"
2023-01-23T15:53:56.536390Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.536392Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.536563Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059593,
    events_root: None,
}
2023-01-23T15:53:56.537961Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/not.json"
2023-01-23T15:53:56.537987Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.564029Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:56.564158Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564162Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:56.564227Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564229Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:56.564286Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564288Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:56.564351Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564354Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:56.564402Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564404Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:56.564480Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564483Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:56.564547Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564550Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:53:56.564599Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564602Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T15:53:56.564650Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564652Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T15:53:56.564711Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564713Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T15:53:56.564766Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564768Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-23T15:53:56.564818Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564820Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-23T15:53:56.564862Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564864Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-23T15:53:56.564911Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564913Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-23T15:53:56.564970Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.564973Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-23T15:53:56.565024Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.565026Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-23T15:53:56.565068Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.565070Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-23T15:53:56.565119Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.565121Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 18
2023-01-23T15:53:56.565178Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.565253Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:56.565257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::2
2023-01-23T15:53:56.565260Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.565263Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.565265Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.909190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034605,
    events_root: None,
}
2023-01-23T15:53:56.909215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-23T15:53:56.909222Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::6
2023-01-23T15:53:56.909224Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.909227Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.909228Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.909418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032637,
    events_root: None,
}
2023-01-23T15:53:56.909427Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-23T15:53:56.909429Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::7
2023-01-23T15:53:56.909431Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.909434Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.909436Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.909612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032606,
    events_root: None,
}
2023-01-23T15:53:56.909622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-23T15:53:56.909624Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::10
2023-01-23T15:53:56.909633Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.909637Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.909638Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.909817Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3033149,
    events_root: None,
}
2023-01-23T15:53:56.909826Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-23T15:53:56.909828Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::11
2023-01-23T15:53:56.909830Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.909833Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.909834Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.910008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032573,
    events_root: None,
}
2023-01-23T15:53:56.910017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 16
2023-01-23T15:53:56.910020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::16
2023-01-23T15:53:56.910022Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.910024Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.910026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.910205Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3035295,
    events_root: None,
}
2023-01-23T15:53:56.910213Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:56.910216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::0
2023-01-23T15:53:56.910218Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.910220Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.910221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.910414Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4006547,
    events_root: None,
}
2023-01-23T15:53:56.910424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:56.910427Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::1
2023-01-23T15:53:56.910429Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.910431Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.910433Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.910623Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4006547,
    events_root: None,
}
2023-01-23T15:53:56.910632Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:56.910635Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::3
2023-01-23T15:53:56.910637Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.910639Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.910640Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.910830Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003978,
    events_root: None,
}
2023-01-23T15:53:56.910839Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:56.910842Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::4
2023-01-23T15:53:56.910844Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.910847Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.910849Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.911038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003978,
    events_root: None,
}
2023-01-23T15:53:56.911047Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:56.911050Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::5
2023-01-23T15:53:56.911052Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.911054Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.911056Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.911249Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4010012,
    events_root: None,
}
2023-01-23T15:53:56.911258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-23T15:53:56.911261Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::8
2023-01-23T15:53:56.911263Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.911265Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.911268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.911456Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3961812,
    events_root: None,
}
2023-01-23T15:53:56.911466Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-23T15:53:56.911469Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::9
2023-01-23T15:53:56.911471Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.911473Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.911475Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.911663Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003978,
    events_root: None,
}
2023-01-23T15:53:56.911672Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-23T15:53:56.911675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::12
2023-01-23T15:53:56.911677Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.911679Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.911681Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.911870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3959047,
    events_root: None,
}
2023-01-23T15:53:56.911879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-23T15:53:56.911882Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::13
2023-01-23T15:53:56.911884Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.911887Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.911889Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.912077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003978,
    events_root: None,
}
2023-01-23T15:53:56.912086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-23T15:53:56.912088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::15
2023-01-23T15:53:56.912090Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.912093Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.912094Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.912289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4008491,
    events_root: None,
}
2023-01-23T15:53:56.912298Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-23T15:53:56.912301Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Istanbul::14
2023-01-23T15:53:56.912303Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.912306Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.912308Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.912498Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4010012,
    events_root: None,
}
2023-01-23T15:53:56.912507Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:56.912510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::2
2023-01-23T15:53:56.912511Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.912514Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.912515Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.912690Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034605,
    events_root: None,
}
2023-01-23T15:53:56.912698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-23T15:53:56.912701Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::6
2023-01-23T15:53:56.912703Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.912705Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.912707Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.912881Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032637,
    events_root: None,
}
2023-01-23T15:53:56.912890Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-23T15:53:56.912892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::7
2023-01-23T15:53:56.912894Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.912897Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.912898Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.913068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032606,
    events_root: None,
}
2023-01-23T15:53:56.913077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-23T15:53:56.913079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::10
2023-01-23T15:53:56.913081Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.913084Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.913085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.913260Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3033149,
    events_root: None,
}
2023-01-23T15:53:56.913269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-23T15:53:56.913271Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::11
2023-01-23T15:53:56.913273Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.913276Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.913277Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.913450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032573,
    events_root: None,
}
2023-01-23T15:53:56.913458Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-23T15:53:56.913461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::16
2023-01-23T15:53:56.913463Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.913466Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.913467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.913656Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3035295,
    events_root: None,
}
2023-01-23T15:53:56.913665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:56.913668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::0
2023-01-23T15:53:56.913670Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.913672Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.913674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.913869Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067813,
    events_root: None,
}
2023-01-23T15:53:56.913878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:56.913881Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::1
2023-01-23T15:53:56.913883Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.913885Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.913887Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.914061Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067813,
    events_root: None,
}
2023-01-23T15:53:56.914070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:56.914073Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::3
2023-01-23T15:53:56.914075Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.914078Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.914079Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.914259Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.914269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:56.914271Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::4
2023-01-23T15:53:56.914273Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.914276Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.914277Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.914451Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.914460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:56.914462Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::5
2023-01-23T15:53:56.914465Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.914467Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.914468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.914645Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071277,
    events_root: None,
}
2023-01-23T15:53:56.914654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-23T15:53:56.914656Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::8
2023-01-23T15:53:56.914658Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.914661Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.914662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.914837Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3066590,
    events_root: None,
}
2023-01-23T15:53:56.914846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-23T15:53:56.914848Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::9
2023-01-23T15:53:56.914850Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.914853Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.914854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.915029Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.915037Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-23T15:53:56.915040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::12
2023-01-23T15:53:56.915042Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.915044Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.915046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.915225Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063824,
    events_root: None,
}
2023-01-23T15:53:56.915234Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-23T15:53:56.915236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::13
2023-01-23T15:53:56.915238Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.915241Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.915243Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.915417Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.915427Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-23T15:53:56.915429Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::15
2023-01-23T15:53:56.915431Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.915434Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.915435Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.915612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3069757,
    events_root: None,
}
2023-01-23T15:53:56.915620Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-23T15:53:56.915623Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Berlin::14
2023-01-23T15:53:56.915625Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.915627Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.915629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.915804Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071277,
    events_root: None,
}
2023-01-23T15:53:56.915813Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:56.915815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::2
2023-01-23T15:53:56.915817Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.915820Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.915821Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.915994Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034605,
    events_root: None,
}
2023-01-23T15:53:56.916003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T15:53:56.916005Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::6
2023-01-23T15:53:56.916007Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.916010Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.916011Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.916185Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032637,
    events_root: None,
}
2023-01-23T15:53:56.916194Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T15:53:56.916197Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::7
2023-01-23T15:53:56.916199Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.916201Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.916202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.916372Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032606,
    events_root: None,
}
2023-01-23T15:53:56.916381Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-23T15:53:56.916383Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::10
2023-01-23T15:53:56.916385Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.916388Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.916389Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.916560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3033149,
    events_root: None,
}
2023-01-23T15:53:56.916568Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-23T15:53:56.916571Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::11
2023-01-23T15:53:56.916573Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.916576Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.916578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.916748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032573,
    events_root: None,
}
2023-01-23T15:53:56.916756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-23T15:53:56.916759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::16
2023-01-23T15:53:56.916762Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.916764Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.916765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.916937Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3035295,
    events_root: None,
}
2023-01-23T15:53:56.916956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:56.916959Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::0
2023-01-23T15:53:56.916961Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.916963Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.916965Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.917140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067813,
    events_root: None,
}
2023-01-23T15:53:56.917150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:56.917153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::1
2023-01-23T15:53:56.917156Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.917158Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.917160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.917416Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067813,
    events_root: None,
}
2023-01-23T15:53:56.917424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:56.917427Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::3
2023-01-23T15:53:56.917429Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.917432Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.917434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.917620Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.917636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:56.917639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::4
2023-01-23T15:53:56.917641Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.917643Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.917645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.917824Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.917833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:56.917835Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::5
2023-01-23T15:53:56.917837Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.917840Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.917841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.918018Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071277,
    events_root: None,
}
2023-01-23T15:53:56.918026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T15:53:56.918029Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::8
2023-01-23T15:53:56.918031Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.918034Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.918035Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.918214Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3066590,
    events_root: None,
}
2023-01-23T15:53:56.918223Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-23T15:53:56.918226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::9
2023-01-23T15:53:56.918228Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.918230Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.918232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.918405Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.918414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-23T15:53:56.918418Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::12
2023-01-23T15:53:56.918420Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.918422Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.918424Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.918597Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063824,
    events_root: None,
}
2023-01-23T15:53:56.918607Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-23T15:53:56.918609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::13
2023-01-23T15:53:56.918611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.918614Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.918615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.918790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.918798Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-23T15:53:56.918801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::15
2023-01-23T15:53:56.918803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.918806Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.918807Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.918982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3069757,
    events_root: None,
}
2023-01-23T15:53:56.918990Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-23T15:53:56.918993Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::London::14
2023-01-23T15:53:56.918995Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.918997Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.918999Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.919179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071277,
    events_root: None,
}
2023-01-23T15:53:56.919188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:56.919191Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::2
2023-01-23T15:53:56.919193Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.919195Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.919197Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.919368Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034605,
    events_root: None,
}
2023-01-23T15:53:56.919377Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T15:53:56.919379Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::6
2023-01-23T15:53:56.919381Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.919385Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.919386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.919555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032637,
    events_root: None,
}
2023-01-23T15:53:56.919564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T15:53:56.919566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::7
2023-01-23T15:53:56.919569Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.919571Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.919573Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.919743Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032606,
    events_root: None,
}
2023-01-23T15:53:56.919753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-23T15:53:56.919756Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::10
2023-01-23T15:53:56.919757Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.919761Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.919763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.919931Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3033149,
    events_root: None,
}
2023-01-23T15:53:56.919940Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-23T15:53:56.919944Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::11
2023-01-23T15:53:56.919946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.919948Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.919949Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.920118Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3032573,
    events_root: None,
}
2023-01-23T15:53:56.920127Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-23T15:53:56.920130Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::16
2023-01-23T15:53:56.920132Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.920134Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.920135Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.920305Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3035295,
    events_root: None,
}
2023-01-23T15:53:56.920315Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:56.920317Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::0
2023-01-23T15:53:56.920319Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.920322Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.920323Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.920514Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067813,
    events_root: None,
}
2023-01-23T15:53:56.920524Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:56.920527Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::1
2023-01-23T15:53:56.920529Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.920531Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.920532Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.920742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3067813,
    events_root: None,
}
2023-01-23T15:53:56.920751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:56.920753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::3
2023-01-23T15:53:56.920755Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.920758Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.920759Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.920945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.920956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:56.920959Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::4
2023-01-23T15:53:56.920961Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.920964Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.920967Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.921209Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.921219Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:56.921222Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::5
2023-01-23T15:53:56.921224Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.921227Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.921229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.921409Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071277,
    events_root: None,
}
2023-01-23T15:53:56.921418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T15:53:56.921420Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::8
2023-01-23T15:53:56.921423Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.921425Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.921427Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.921601Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3066590,
    events_root: None,
}
2023-01-23T15:53:56.921609Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-23T15:53:56.921612Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::9
2023-01-23T15:53:56.921614Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.921616Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.921618Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.921800Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.921809Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-23T15:53:56.921812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::12
2023-01-23T15:53:56.921814Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.921816Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.921817Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.921992Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3063824,
    events_root: None,
}
2023-01-23T15:53:56.922001Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-23T15:53:56.922003Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::13
2023-01-23T15:53:56.922005Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.922008Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.922010Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.922190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065724,
    events_root: None,
}
2023-01-23T15:53:56.922199Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-23T15:53:56.922203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::15
2023-01-23T15:53:56.922205Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.922207Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.922209Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.922386Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3069757,
    events_root: None,
}
2023-01-23T15:53:56.922394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-23T15:53:56.922396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdiv"::Merge::14
2023-01-23T15:53:56.922399Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.922401Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.922402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:56.922579Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3071277,
    events_root: None,
}
2023-01-23T15:53:56.924247Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sdiv.json"
2023-01-23T15:53:56.924277Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:56.950155Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:56.950266Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950270Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:56.950321Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950323Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:56.950380Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950382Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:56.950433Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950435Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:56.950483Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950485Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:56.950543Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950545Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:56.950600Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950602Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:53:56.950645Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950647Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T15:53:56.950689Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950691Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T15:53:56.950755Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950758Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T15:53:56.950804Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950806Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-23T15:53:56.950855Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950858Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-23T15:53:56.950905Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950907Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-23T15:53:56.950950Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.950952Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-23T15:53:56.951006Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.951009Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-23T15:53:56.951060Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.951062Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-23T15:53:56.951117Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:56.951229Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:56.951235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::1
2023-01-23T15:53:56.951239Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:56.951243Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:56.951245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.283736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030219,
    events_root: None,
}
2023-01-23T15:53:57.283758Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-23T15:53:57.283765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::6
2023-01-23T15:53:57.283768Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.283771Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.283772Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.283960Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030781,
    events_root: None,
}
2023-01-23T15:53:57.283969Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:57.283972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::0
2023-01-23T15:53:57.283974Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.283977Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.283978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.284179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3957180,
    events_root: None,
}
2023-01-23T15:53:57.284190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:57.284193Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::2
2023-01-23T15:53:57.284195Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.284197Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.284199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.284384Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000197,
    events_root: None,
}
2023-01-23T15:53:57.284396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:57.284398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::3
2023-01-23T15:53:57.284400Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.284403Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.284404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.284589Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000992,
    events_root: None,
}
2023-01-23T15:53:57.284601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:57.284603Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::4
2023-01-23T15:53:57.284605Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.284608Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.284610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.284795Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000992,
    events_root: None,
}
2023-01-23T15:53:57.284806Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:57.284809Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::5
2023-01-23T15:53:57.284811Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.284813Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.284815Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.285007Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954649,
    events_root: None,
}
2023-01-23T15:53:57.285018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-23T15:53:57.285021Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::7
2023-01-23T15:53:57.285023Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.285026Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.285027Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.285215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955179,
    events_root: None,
}
2023-01-23T15:53:57.285226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-23T15:53:57.285229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::8
2023-01-23T15:53:57.285232Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.285235Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.285237Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.285481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3956481,
    events_root: None,
}
2023-01-23T15:53:57.285496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-23T15:53:57.285500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::9
2023-01-23T15:53:57.285502Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.285505Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.285506Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.285705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3999152,
    events_root: None,
}
2023-01-23T15:53:57.285717Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-23T15:53:57.285719Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::10
2023-01-23T15:53:57.285722Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.285724Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.285726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.285912Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3956050,
    events_root: None,
}
2023-01-23T15:53:57.285924Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-23T15:53:57.285926Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::11
2023-01-23T15:53:57.285928Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.285931Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.285932Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.286116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955893,
    events_root: None,
}
2023-01-23T15:53:57.286129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-23T15:53:57.286132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::12
2023-01-23T15:53:57.286134Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.286137Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.286138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.286322Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3999152,
    events_root: None,
}
2023-01-23T15:53:57.286334Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-23T15:53:57.286336Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::13
2023-01-23T15:53:57.286338Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.286341Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.286342Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.286529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955438,
    events_root: None,
}
2023-01-23T15:53:57.286540Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-23T15:53:57.286543Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Istanbul::14
2023-01-23T15:53:57.286544Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.286547Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.286548Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.286748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4001222,
    events_root: None,
}
2023-01-23T15:53:57.286760Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:57.286763Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::1
2023-01-23T15:53:57.286765Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.286768Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.286769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.286953Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030219,
    events_root: None,
}
2023-01-23T15:53:57.286962Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-23T15:53:57.286964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::6
2023-01-23T15:53:57.286966Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.286969Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.286970Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.287199Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030781,
    events_root: None,
}
2023-01-23T15:53:57.287209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:57.287212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::0
2023-01-23T15:53:57.287214Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.287216Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.287218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.287396Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059010,
    events_root: None,
}
2023-01-23T15:53:57.287405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:57.287408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::2
2023-01-23T15:53:57.287410Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.287412Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.287414Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.287584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061099,
    events_root: None,
}
2023-01-23T15:53:57.287593Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:57.287595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::3
2023-01-23T15:53:57.287597Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.287600Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.287602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.287776Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062257,
    events_root: None,
}
2023-01-23T15:53:57.287785Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:57.287787Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::4
2023-01-23T15:53:57.287789Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.287792Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.287793Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.287970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062257,
    events_root: None,
}
2023-01-23T15:53:57.287979Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:57.287981Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::5
2023-01-23T15:53:57.287983Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.287986Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.287987Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.288160Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059427,
    events_root: None,
}
2023-01-23T15:53:57.288168Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-23T15:53:57.288170Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::7
2023-01-23T15:53:57.288173Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.288175Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.288176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.288347Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059592,
    events_root: None,
}
2023-01-23T15:53:57.288356Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-23T15:53:57.288359Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::8
2023-01-23T15:53:57.288361Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.288363Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.288365Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.288535Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059603,
    events_root: None,
}
2023-01-23T15:53:57.288544Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-23T15:53:57.288547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::9
2023-01-23T15:53:57.288549Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.288551Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.288552Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.288782Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060897,
    events_root: None,
}
2023-01-23T15:53:57.288793Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-23T15:53:57.288797Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::10
2023-01-23T15:53:57.288799Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.288802Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.288803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.288983Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059172,
    events_root: None,
}
2023-01-23T15:53:57.288991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-23T15:53:57.288994Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::11
2023-01-23T15:53:57.288997Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.288999Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.289000Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.289173Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059015,
    events_root: None,
}
2023-01-23T15:53:57.289182Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-23T15:53:57.289185Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::12
2023-01-23T15:53:57.289187Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.289190Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.289191Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.289362Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060897,
    events_root: None,
}
2023-01-23T15:53:57.289371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-23T15:53:57.289373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::13
2023-01-23T15:53:57.289376Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.289378Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.289379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.289550Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059851,
    events_root: None,
}
2023-01-23T15:53:57.289559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-23T15:53:57.289561Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Berlin::14
2023-01-23T15:53:57.289563Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.289566Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.289567Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.289750Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062968,
    events_root: None,
}
2023-01-23T15:53:57.289759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:57.289761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::1
2023-01-23T15:53:57.289763Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.289766Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.289767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.289940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030219,
    events_root: None,
}
2023-01-23T15:53:57.289949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-23T15:53:57.289952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::6
2023-01-23T15:53:57.289953Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.289956Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.289958Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.290123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030781,
    events_root: None,
}
2023-01-23T15:53:57.290132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:57.290135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::0
2023-01-23T15:53:57.290137Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.290139Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.290141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.290367Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059010,
    events_root: None,
}
2023-01-23T15:53:57.290379Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:57.290382Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::2
2023-01-23T15:53:57.290385Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.290387Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.290389Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.290562Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061099,
    events_root: None,
}
2023-01-23T15:53:57.290571Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:57.290573Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::3
2023-01-23T15:53:57.290576Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.290578Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.290580Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.290750Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062257,
    events_root: None,
}
2023-01-23T15:53:57.290759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:57.290761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::4
2023-01-23T15:53:57.290763Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.290767Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.290768Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.290943Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062257,
    events_root: None,
}
2023-01-23T15:53:57.290952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:57.290955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::5
2023-01-23T15:53:57.290957Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.290960Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.290961Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.291130Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059427,
    events_root: None,
}
2023-01-23T15:53:57.291139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-23T15:53:57.291141Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::7
2023-01-23T15:53:57.291144Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.291147Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.291148Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.291320Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059592,
    events_root: None,
}
2023-01-23T15:53:57.291329Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-23T15:53:57.291331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::8
2023-01-23T15:53:57.291333Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.291336Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.291337Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.291509Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059603,
    events_root: None,
}
2023-01-23T15:53:57.291517Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-23T15:53:57.291520Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::9
2023-01-23T15:53:57.291522Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.291524Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.291525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.291697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060897,
    events_root: None,
}
2023-01-23T15:53:57.291705Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-23T15:53:57.291708Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::10
2023-01-23T15:53:57.291710Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.291713Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.291714Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.291885Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059172,
    events_root: None,
}
2023-01-23T15:53:57.291894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-23T15:53:57.291897Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::11
2023-01-23T15:53:57.291900Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.291904Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.291906Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.292134Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059015,
    events_root: None,
}
2023-01-23T15:53:57.292144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-23T15:53:57.292147Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::12
2023-01-23T15:53:57.292149Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.292151Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.292153Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.292329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060897,
    events_root: None,
}
2023-01-23T15:53:57.292337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-23T15:53:57.292340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::13
2023-01-23T15:53:57.292342Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.292345Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.292346Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.292516Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059851,
    events_root: None,
}
2023-01-23T15:53:57.292524Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-23T15:53:57.292527Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::London::14
2023-01-23T15:53:57.292529Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.292531Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.292533Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.292704Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062968,
    events_root: None,
}
2023-01-23T15:53:57.292713Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:57.292716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::1
2023-01-23T15:53:57.292718Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.292721Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.292722Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.292893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030219,
    events_root: None,
}
2023-01-23T15:53:57.292902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-23T15:53:57.292905Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::6
2023-01-23T15:53:57.292907Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.292909Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.292911Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.293077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030781,
    events_root: None,
}
2023-01-23T15:53:57.293086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:57.293088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::0
2023-01-23T15:53:57.293091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.293093Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.293095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.293266Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059010,
    events_root: None,
}
2023-01-23T15:53:57.293274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:57.293277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::2
2023-01-23T15:53:57.293279Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.293281Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.293283Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.293453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061099,
    events_root: None,
}
2023-01-23T15:53:57.293461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:57.293465Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::3
2023-01-23T15:53:57.293468Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.293471Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.293473Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.293718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062257,
    events_root: None,
}
2023-01-23T15:53:57.293727Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:57.293730Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::4
2023-01-23T15:53:57.293733Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.293735Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.293737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.293910Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062257,
    events_root: None,
}
2023-01-23T15:53:57.293919Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:57.293922Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::5
2023-01-23T15:53:57.293924Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.293926Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.293928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.294098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059427,
    events_root: None,
}
2023-01-23T15:53:57.294107Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-23T15:53:57.294110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::7
2023-01-23T15:53:57.294112Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.294114Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.294116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.294288Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059592,
    events_root: None,
}
2023-01-23T15:53:57.294297Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-23T15:53:57.294300Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::8
2023-01-23T15:53:57.294302Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.294304Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.294306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.294483Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059603,
    events_root: None,
}
2023-01-23T15:53:57.294492Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-23T15:53:57.294495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::9
2023-01-23T15:53:57.294497Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.294500Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.294501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.294672Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060897,
    events_root: None,
}
2023-01-23T15:53:57.294681Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-23T15:53:57.294685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::10
2023-01-23T15:53:57.294687Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.294690Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.294691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.294863Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059172,
    events_root: None,
}
2023-01-23T15:53:57.294872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-23T15:53:57.294874Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::11
2023-01-23T15:53:57.294876Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.294879Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.294880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.295051Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059015,
    events_root: None,
}
2023-01-23T15:53:57.295060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-23T15:53:57.295062Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::12
2023-01-23T15:53:57.295064Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.295067Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.295068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.295297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060897,
    events_root: None,
}
2023-01-23T15:53:57.295308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-23T15:53:57.295311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::13
2023-01-23T15:53:57.295313Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.295315Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.295317Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.295490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3059851,
    events_root: None,
}
2023-01-23T15:53:57.295499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-23T15:53:57.295501Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextend"::Merge::14
2023-01-23T15:53:57.295504Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.295506Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.295508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.295679Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3062968,
    events_root: None,
}
2023-01-23T15:53:57.296972Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/signextend.json"
2023-01-23T15:53:57.296999Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.321393Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:57.321494Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.321497Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:57.321548Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.321550Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:57.321605Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.321607Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:57.321669Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.321672Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:57.321717Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.321719Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:57.321779Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.321781Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:57.321836Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.321838Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T15:53:57.321883Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.321958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:57.321962Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Istanbul::0
2023-01-23T15:53:57.321965Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.321968Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.321969Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.692038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3957506,
    events_root: None,
}
2023-01-23T15:53:57.692063Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:57.692069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Istanbul::1
2023-01-23T15:53:57.692071Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.692074Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.692075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.692276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000673,
    events_root: None,
}
2023-01-23T15:53:57.692288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:57.692291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Istanbul::2
2023-01-23T15:53:57.692293Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.692295Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.692296Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.692468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030709,
    events_root: None,
}
2023-01-23T15:53:57.692477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:57.692479Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Istanbul::3
2023-01-23T15:53:57.692481Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.692483Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.692485Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.692712Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029519,
    events_root: None,
}
2023-01-23T15:53:57.692723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:57.692727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Istanbul::4
2023-01-23T15:53:57.692730Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.692733Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.692735Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.692935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4003650,
    events_root: None,
}
2023-01-23T15:53:57.692946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-23T15:53:57.692949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Istanbul::5
2023-01-23T15:53:57.692951Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.692954Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.692955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.693140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4000066,
    events_root: None,
}
2023-01-23T15:53:57.693152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:57.693155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Berlin::0
2023-01-23T15:53:57.693157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.693159Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.693161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.693337Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061919,
    events_root: None,
}
2023-01-23T15:53:57.693346Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:57.693349Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Berlin::1
2023-01-23T15:53:57.693351Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.693353Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.693355Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.693529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061575,
    events_root: None,
}
2023-01-23T15:53:57.693537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:57.693540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Berlin::2
2023-01-23T15:53:57.693543Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.693546Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.693548Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.693732Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030709,
    events_root: None,
}
2023-01-23T15:53:57.693741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:57.693744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Berlin::3
2023-01-23T15:53:57.693746Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.693749Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.693750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.693918Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029519,
    events_root: None,
}
2023-01-23T15:53:57.693927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:57.693930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Berlin::4
2023-01-23T15:53:57.693932Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.693934Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.693936Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.694109Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065396,
    events_root: None,
}
2023-01-23T15:53:57.694117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-23T15:53:57.694120Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Berlin::5
2023-01-23T15:53:57.694122Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.694124Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.694126Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.694354Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061812,
    events_root: None,
}
2023-01-23T15:53:57.694366Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:57.694369Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::London::0
2023-01-23T15:53:57.694372Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.694375Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.694376Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.694554Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061919,
    events_root: None,
}
2023-01-23T15:53:57.694564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:57.694567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::London::1
2023-01-23T15:53:57.694569Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.694572Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.694573Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.694747Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061575,
    events_root: None,
}
2023-01-23T15:53:57.694755Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:57.694758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::London::2
2023-01-23T15:53:57.694760Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.694763Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.694765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.694934Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030709,
    events_root: None,
}
2023-01-23T15:53:57.694942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:57.694945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::London::3
2023-01-23T15:53:57.694947Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.694950Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.694951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.695120Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029519,
    events_root: None,
}
2023-01-23T15:53:57.695129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:57.695131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::London::4
2023-01-23T15:53:57.695134Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.695136Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.695137Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.695309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065396,
    events_root: None,
}
2023-01-23T15:53:57.695318Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-23T15:53:57.695321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::London::5
2023-01-23T15:53:57.695323Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.695325Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.695327Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.695500Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061812,
    events_root: None,
}
2023-01-23T15:53:57.695509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:57.695512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Merge::0
2023-01-23T15:53:57.695513Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.695516Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.695518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.695690Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061919,
    events_root: None,
}
2023-01-23T15:53:57.695699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:57.695701Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Merge::1
2023-01-23T15:53:57.695703Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.695706Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.695707Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.695935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061575,
    events_root: None,
}
2023-01-23T15:53:57.695946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:57.695949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Merge::2
2023-01-23T15:53:57.695952Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.695955Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.695957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.696131Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3030709,
    events_root: None,
}
2023-01-23T15:53:57.696139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:57.696142Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Merge::3
2023-01-23T15:53:57.696144Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.696146Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.696148Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.696316Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3029519,
    events_root: None,
}
2023-01-23T15:53:57.696325Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:57.696327Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Merge::4
2023-01-23T15:53:57.696329Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.696332Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.696333Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.696505Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3065396,
    events_root: None,
}
2023-01-23T15:53:57.696514Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-23T15:53:57.696516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smod"::Merge::5
2023-01-23T15:53:57.696518Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.696521Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.696523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:57.696700Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3061812,
    events_root: None,
}
2023-01-23T15:53:57.697859Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/smod.json"
2023-01-23T15:53:57.697887Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:57.722945Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:57.723044Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.723047Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:57.723099Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.723101Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T15:53:57.723157Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.723158Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T15:53:57.723210Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.723212Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T15:53:57.723257Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.723259Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T15:53:57.723323Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.723324Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T15:53:57.723381Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:57.723453Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:57.723458Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Istanbul::0
2023-01-23T15:53:57.723460Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:57.723463Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:57.723464Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.084431Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954414,
    events_root: None,
}
2023-01-23T15:53:58.084457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-23T15:53:58.084465Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Istanbul::1
2023-01-23T15:53:58.084467Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.084470Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.084471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.084673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3998363,
    events_root: None,
}
2023-01-23T15:53:58.084685Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-23T15:53:58.084687Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Istanbul::2
2023-01-23T15:53:58.084689Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.084691Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.084693Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.084883Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3998363,
    events_root: None,
}
2023-01-23T15:53:58.084894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-23T15:53:58.084898Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Istanbul::3
2023-01-23T15:53:58.084899Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.084902Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.084903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.085090Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3955632,
    events_root: None,
}
2023-01-23T15:53:58.085101Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-23T15:53:58.085104Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Istanbul::4
2023-01-23T15:53:58.085106Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.085109Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.085110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.085293Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3999573,
    events_root: None,
}
2023-01-23T15:53:58.085305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:58.085308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Berlin::0
2023-01-23T15:53:58.085310Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.085312Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.085314Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.085490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058827,
    events_root: None,
}
2023-01-23T15:53:58.085498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-23T15:53:58.085501Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Berlin::1
2023-01-23T15:53:58.085503Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.085506Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.085507Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.085731Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060109,
    events_root: None,
}
2023-01-23T15:53:58.085741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-23T15:53:58.085744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Berlin::2
2023-01-23T15:53:58.085746Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.085748Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.085749Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.085968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060109,
    events_root: None,
}
2023-01-23T15:53:58.085978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-23T15:53:58.085982Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Berlin::3
2023-01-23T15:53:58.085984Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.085988Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.085990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.086215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060410,
    events_root: None,
}
2023-01-23T15:53:58.086224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-23T15:53:58.086227Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Berlin::4
2023-01-23T15:53:58.086228Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.086231Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.086232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.086461Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060475,
    events_root: None,
}
2023-01-23T15:53:58.086470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:58.086473Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::London::0
2023-01-23T15:53:58.086475Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.086477Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.086478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.086661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058827,
    events_root: None,
}
2023-01-23T15:53:58.086670Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-23T15:53:58.086673Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::London::1
2023-01-23T15:53:58.086675Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.086677Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.086679Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.086852Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060109,
    events_root: None,
}
2023-01-23T15:53:58.086861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-23T15:53:58.086863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::London::2
2023-01-23T15:53:58.086865Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.086868Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.086869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.087039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060109,
    events_root: None,
}
2023-01-23T15:53:58.087047Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-23T15:53:58.087050Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::London::3
2023-01-23T15:53:58.087053Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.087056Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.087057Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.087228Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060410,
    events_root: None,
}
2023-01-23T15:53:58.087237Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-23T15:53:58.087239Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::London::4
2023-01-23T15:53:58.087241Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.087244Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.087245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.087417Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060475,
    events_root: None,
}
2023-01-23T15:53:58.087426Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:58.087428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Merge::0
2023-01-23T15:53:58.087430Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.087433Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.087434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.087604Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3058827,
    events_root: None,
}
2023-01-23T15:53:58.087613Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-23T15:53:58.087615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Merge::1
2023-01-23T15:53:58.087617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.087619Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.087621Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.087792Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060109,
    events_root: None,
}
2023-01-23T15:53:58.087800Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-23T15:53:58.087803Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Merge::2
2023-01-23T15:53:58.087805Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.087807Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.087808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.087980Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060109,
    events_root: None,
}
2023-01-23T15:53:58.087988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-23T15:53:58.087991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Merge::3
2023-01-23T15:53:58.087993Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.087995Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.087996Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.088176Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060410,
    events_root: None,
}
2023-01-23T15:53:58.088185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-23T15:53:58.088187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sub"::Merge::4
2023-01-23T15:53:58.088189Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.088191Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-23T15:53:58.088193Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.088367Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3060475,
    events_root: None,
}
2023-01-23T15:53:58.089899Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/sub.json"
2023-01-23T15:53:58.089925Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/twoOps.json"
2023-01-23T15:53:58.116081Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T15:53:58.116190Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:58.116193Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T15:53:58.116315Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T15:53:58.116388Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T15:53:58.116392Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "twoOps"::Istanbul::0
2023-01-23T15:53:58.116395Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/twoOps.json"
2023-01-23T15:53:58.116398Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:58.116399Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.465386Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 250589200,
    events_root: None,
}
2023-01-23T15:53:58.465481Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T15:53:58.465492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "twoOps"::Berlin::0
2023-01-23T15:53:58.465496Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/twoOps.json"
2023-01-23T15:53:58.465501Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:58.465503Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.473580Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 182698695,
    events_root: None,
}
2023-01-23T15:53:58.473671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T15:53:58.473678Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "twoOps"::London::0
2023-01-23T15:53:58.473681Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/twoOps.json"
2023-01-23T15:53:58.473684Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:58.473686Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.481477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 182698695,
    events_root: None,
}
2023-01-23T15:53:58.481565Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T15:53:58.481571Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "twoOps"::Merge::0
2023-01-23T15:53:58.481574Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/twoOps.json"
2023-01-23T15:53:58.481577Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-23T15:53:58.481578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T15:53:58.489343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 182698695,
    events_root: None,
}
2023-01-23T15:53:58.490894Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmArithmeticTest/twoOps.json"
2023-01-23T15:53:58.491007Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 19 Files in Time:6.98091784s
```