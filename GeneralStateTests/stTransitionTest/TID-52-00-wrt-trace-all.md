> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stTransitionTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stTransitionTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution OK, all use-case passed.

> Execution Trace

```
2023-01-24T09:37:18.215635Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stTransitionTest", Total Files :: 6
2023-01-24T09:37:18.215903Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAfter.json"
2023-01-24T09:37:18.245126Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:37:18.245316Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:18.245387Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:37:18.245391Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsAfter"::Istanbul::0
2023-01-24T09:37:18.245394Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAfter.json"
2023-01-24T09:37:18.245397Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.245398Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:37:18.245400Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsAfter"::Berlin::0
2023-01-24T09:37:18.245402Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAfter.json"
2023-01-24T09:37:18.245405Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.245406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:37:18.245407Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsAfter"::London::0
2023-01-24T09:37:18.245409Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAfter.json"
2023-01-24T09:37:18.245412Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.245413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:37:18.245415Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsAfter"::Merge::0
2023-01-24T09:37:18.245417Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAfter.json"
2023-01-24T09:37:18.245419Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.245818Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAfter.json"
2023-01-24T09:37:18.245845Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAt.json"
2023-01-24T09:37:18.270222Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:37:18.270324Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:18.270394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:37:18.270399Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsAt"::Istanbul::0
2023-01-24T09:37:18.270401Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAt.json"
2023-01-24T09:37:18.270405Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.270406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:37:18.270408Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsAt"::Berlin::0
2023-01-24T09:37:18.270410Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAt.json"
2023-01-24T09:37:18.270412Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.270413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:37:18.270415Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsAt"::London::0
2023-01-24T09:37:18.270417Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAt.json"
2023-01-24T09:37:18.270419Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.270421Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:37:18.270423Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsAt"::Merge::0
2023-01-24T09:37:18.270424Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAt.json"
2023-01-24T09:37:18.270427Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.270855Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAt.json"
2023-01-24T09:37:18.270876Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsBefore.json"
2023-01-24T09:37:18.295279Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:37:18.295380Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:18.295450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:37:18.295454Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsBefore"::Istanbul::0
2023-01-24T09:37:18.295457Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsBefore.json"
2023-01-24T09:37:18.295460Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.295461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:37:18.295463Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsBefore"::Berlin::0
2023-01-24T09:37:18.295465Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsBefore.json"
2023-01-24T09:37:18.295467Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.295468Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:37:18.295470Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsBefore"::London::0
2023-01-24T09:37:18.295471Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsBefore.json"
2023-01-24T09:37:18.295474Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.295475Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:37:18.295476Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsBefore"::Merge::0
2023-01-24T09:37:18.295478Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsBefore.json"
2023-01-24T09:37:18.295481Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-24T09:37:18.295941Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsBefore.json"
2023-01-24T09:37:18.295965Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAfterTransition.json"
2023-01-24T09:37:18.320055Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:37:18.320154Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:18.320158Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:37:18.320209Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:18.320211Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:37:18.320267Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:18.320336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:37:18.320341Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAfterTransition"::Istanbul::0
2023-01-24T09:37:18.320344Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAfterTransition.json"
2023-01-24T09:37:18.320348Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:18.320349Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:18.725393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:18.725422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:37:18.725431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAfterTransition"::Berlin::0
2023-01-24T09:37:18.725434Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAfterTransition.json"
2023-01-24T09:37:18.725438Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:18.725440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:18.725736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:18.725746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:37:18.725749Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAfterTransition"::London::0
2023-01-24T09:37:18.725751Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAfterTransition.json"
2023-01-24T09:37:18.725753Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:18.725755Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:18.725978Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:18.725988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:37:18.725990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAfterTransition"::Merge::0
2023-01-24T09:37:18.725992Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAfterTransition.json"
2023-01-24T09:37:18.725995Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:18.725997Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:18.726213Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:18.727978Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAfterTransition.json"
2023-01-24T09:37:18.728012Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAtTransition.json"
2023-01-24T09:37:18.754916Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:37:18.755042Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:18.755047Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:37:18.755121Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:18.755125Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:37:18.755204Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:18.755304Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:37:18.755313Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAtTransition"::Istanbul::0
2023-01-24T09:37:18.755316Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAtTransition.json"
2023-01-24T09:37:18.755320Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:18.755321Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:19.098573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:19.098598Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:37:19.098607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAtTransition"::Berlin::0
2023-01-24T09:37:19.098610Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAtTransition.json"
2023-01-24T09:37:19.098615Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:19.098616Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:19.098857Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:19.098868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:37:19.098873Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAtTransition"::London::0
2023-01-24T09:37:19.098876Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAtTransition.json"
2023-01-24T09:37:19.098879Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:19.098882Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:19.099102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:19.099112Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:37:19.099117Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallAtTransition"::Merge::0
2023-01-24T09:37:19.099120Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAtTransition.json"
2023-01-24T09:37:19.099125Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:19.099127Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:19.099369Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:19.100657Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallAtTransition.json"
2023-01-24T09:37:19.100686Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallBeforeTransition.json"
2023-01-24T09:37:19.125685Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:37:19.125824Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:19.125830Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:37:19.125904Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:19.125908Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:37:19.125988Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:37:19.126089Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:37:19.126098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallBeforeTransition"::Istanbul::0
2023-01-24T09:37:19.126101Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallBeforeTransition.json"
2023-01-24T09:37:19.126105Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:19.126108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:19.452130Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:19.452156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:37:19.452162Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallBeforeTransition"::Berlin::0
2023-01-24T09:37:19.452165Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallBeforeTransition.json"
2023-01-24T09:37:19.452168Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:19.452170Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:19.452399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:19.452409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:37:19.452412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallBeforeTransition"::London::0
2023-01-24T09:37:19.452415Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallBeforeTransition.json"
2023-01-24T09:37:19.452417Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:19.452419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:19.452641Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:19.452650Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:37:19.452653Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallBeforeTransition"::Merge::0
2023-01-24T09:37:19.452655Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallBeforeTransition.json"
2023-01-24T09:37:19.452658Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:37:19.452659Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:37:19.452906Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3096713,
    events_root: None,
}
2023-01-24T09:37:19.454538Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stTransitionTest/delegatecallBeforeTransition.json"
2023-01-24T09:37:19.454655Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 6 Files in Time:1.078587809s
```