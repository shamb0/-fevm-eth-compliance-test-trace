> Command Executed

```
clear && \
	RUST_LOG=revme=trace \
	cargo run --release -p revme \
	-- \
	statetest \
	-s ./bins/revme/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json
```

> Execution Trace

```
2023-02-26T15:53:52.677877Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json", Total Files :: 1
2023-02-26T15:53:52.678105Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-26T15:53:52.705746Z TRACE fvm::engine: preloading code CID bafk2bzacebpupmng24invprlbcu22mfhojc3hlwjy5s5ayvle22ocrvzu4ulo
2023-02-26T15:53:52.706687Z DEBUG fvm::machine::default: initializing a new machine, epoch=0, base_fee=0.00000000000000001, nv=NetworkVersion(18), root=bafy2bzacedm7noi7bx77ixysy22eeekkr3gimgz7ruh226m2jaflidwuzzbeg
2023-02-26T15:53:52.706729Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-26T15:53:52.706799Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: true
2023-02-26T15:53:52.706802Z  INFO fvm::executor::default: is_account_actor :: true
2023-02-26T15:53:52.706804Z  INFO fvm::executor::default: is_ethaccount_actor :: false
2023-02-26T15:53:52.706805Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.706807Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.706809Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: false
2023-02-26T15:53:52.706811Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.706812Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.706815Z  INFO fvm::state_tree: Self Balance :: 100000000
2023-02-26T15:53:52.706818Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.706835Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.706849Z TRACE fvm::gas: charging gas: OnCreateActor 2700000.000
2023-02-26T15:53:52.706871Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:52.706874Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:52.706877Z TRACE fvm::call_manager::default: sent 100 -> 400: 0.0
2023-02-26T15:53:52.706895Z  INFO evm_eth_compliance::statetest::executor: Pre Acc 0x0000000000000000000000000000000000000100
2023-02-26T15:53:52.706899Z  INFO evm_eth_compliance::statetest::executor: Balance :: 0
2023-02-26T15:53:52.706901Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-26T15:53:52.706903Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-26T15:53:52.706923Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: true
2023-02-26T15:53:52.706925Z  INFO fvm::executor::default: is_account_actor :: true
2023-02-26T15:53:52.706926Z  INFO fvm::executor::default: is_ethaccount_actor :: false
2023-02-26T15:53:52.706928Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.706930Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.706932Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: false
2023-02-26T15:53:52.706933Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.706935Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.706937Z  INFO fvm::state_tree: Self Balance :: 100000000
2023-02-26T15:53:52.706939Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.706952Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.706965Z TRACE fvm::gas: charging gas: OnCreateActor 2700000.000
2023-02-26T15:53:52.706986Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:52.706988Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:52.706990Z TRACE fvm::call_manager::default: sent 101 -> 401: 0.0
2023-02-26T15:53:52.707005Z  INFO evm_eth_compliance::statetest::executor: Pre Acc 0x0000000000000000000000000000000000000200
2023-02-26T15:53:52.707007Z  INFO evm_eth_compliance::statetest::executor: Balance :: 0
2023-02-26T15:53:52.707009Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-26T15:53:52.707010Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-26T15:53:52.707037Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: true
2023-02-26T15:53:52.707039Z  INFO fvm::executor::default: is_account_actor :: true
2023-02-26T15:53:52.707040Z  INFO fvm::executor::default: is_ethaccount_actor :: false
2023-02-26T15:53:52.707042Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.707044Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.707046Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: false
2023-02-26T15:53:52.707047Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.707049Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.707051Z  INFO fvm::state_tree: Self Balance :: 100000000
2023-02-26T15:53:52.707053Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.707067Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.707078Z TRACE fvm::gas: charging gas: OnCreateActor 2700000.000
2023-02-26T15:53:52.707100Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:52.707102Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:52.707104Z TRACE fvm::call_manager::default: sent 102 -> 402: 0.0
2023-02-26T15:53:52.707116Z  INFO evm_eth_compliance::statetest::executor: Pre Acc 0x0000000000000000000000000000000000000300
2023-02-26T15:53:52.707118Z  INFO evm_eth_compliance::statetest::executor: Balance :: 0
2023-02-26T15:53:52.707120Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-26T15:53:52.707121Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 3
2023-02-26T15:53:52.707145Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: true
2023-02-26T15:53:52.707147Z  INFO fvm::executor::default: is_account_actor :: true
2023-02-26T15:53:52.707149Z  INFO fvm::executor::default: is_ethaccount_actor :: false
2023-02-26T15:53:52.707150Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.707152Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.707153Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: false
2023-02-26T15:53:52.707155Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.707156Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.707158Z  INFO fvm::state_tree: Self Balance :: 100000000
2023-02-26T15:53:52.707161Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.707169Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.707177Z TRACE fvm::gas: charging gas: OnCreateActor 2700000.000
2023-02-26T15:53:52.707192Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:52.707194Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:52.707196Z TRACE fvm::call_manager::default: sent 103 -> 403: 0.0
2023-02-26T15:53:52.707211Z  INFO evm_eth_compliance::statetest::executor: Pre Acc 0x0000000000000000000000000000000000000400
2023-02-26T15:53:52.707213Z  INFO evm_eth_compliance::statetest::executor: Balance :: 0
2023-02-26T15:53:52.707215Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-26T15:53:52.707217Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 4
2023-02-26T15:53:52.707238Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: true
2023-02-26T15:53:52.707240Z  INFO fvm::executor::default: is_account_actor :: true
2023-02-26T15:53:52.707242Z  INFO fvm::executor::default: is_ethaccount_actor :: false
2023-02-26T15:53:52.707244Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.707245Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.707247Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: false
2023-02-26T15:53:52.707249Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.707251Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.707253Z  INFO fvm::state_tree: Self Balance :: 100000000
2023-02-26T15:53:52.707255Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.707268Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.707280Z TRACE fvm::gas: charging gas: OnCreateActor 2700000.000
2023-02-26T15:53:52.707300Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:52.707302Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:52.707304Z TRACE fvm::call_manager::default: sent 104 -> 404: 0.0
2023-02-26T15:53:52.707312Z  INFO evm_eth_compliance::statetest::executor: Pre Acc 0x0000000000000000000000000000000000000500
2023-02-26T15:53:52.707314Z  INFO evm_eth_compliance::statetest::executor: Balance :: 0
2023-02-26T15:53:52.707316Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-26T15:53:52.707317Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 5
2023-02-26T15:53:52.707356Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: true
2023-02-26T15:53:52.707359Z  INFO fvm::executor::default: is_account_actor :: true
2023-02-26T15:53:52.707362Z  INFO fvm::executor::default: is_ethaccount_actor :: false
2023-02-26T15:53:52.707364Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.707366Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.707369Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: false
2023-02-26T15:53:52.707370Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.707372Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.707374Z  INFO fvm::state_tree: Self Balance :: 100000000
2023-02-26T15:53:52.707376Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.707391Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.707402Z TRACE fvm::gas: charging gas: OnCreateActor 2700000.000
2023-02-26T15:53:52.707423Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:52.707425Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:52.707427Z TRACE fvm::call_manager::default: sent 105 -> 405: 0.0
2023-02-26T15:53:52.707435Z  INFO evm_eth_compliance::statetest::executor: Pre Acc 0x0000000000000000000000000000000000000600
2023-02-26T15:53:52.707437Z  INFO evm_eth_compliance::statetest::executor: Balance :: 0
2023-02-26T15:53:52.707439Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-26T15:53:52.707440Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 6
2023-02-26T15:53:52.707464Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: true
2023-02-26T15:53:52.707466Z  INFO fvm::executor::default: is_account_actor :: true
2023-02-26T15:53:52.707468Z  INFO fvm::executor::default: is_ethaccount_actor :: false
2023-02-26T15:53:52.707469Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.707471Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.707473Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: false
2023-02-26T15:53:52.707474Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.707476Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.707478Z  INFO fvm::state_tree: Self Balance :: 100000000
2023-02-26T15:53:52.707480Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.707491Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.707501Z TRACE fvm::gas: charging gas: OnCreateActor 2700000.000
2023-02-26T15:53:52.707520Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:52.707522Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:52.707525Z TRACE fvm::call_manager::default: sent 106 -> 406: 0.0
2023-02-26T15:53:52.707532Z  INFO evm_eth_compliance::statetest::executor: Pre Acc 0x0000000000000000000000000000000000000700
2023-02-26T15:53:52.707534Z  INFO evm_eth_compliance::statetest::executor: Balance :: 0
2023-02-26T15:53:52.707536Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-26T15:53:52.707537Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 7
2023-02-26T15:53:52.707551Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: true
2023-02-26T15:53:52.707553Z  INFO fvm::executor::default: is_account_actor :: true
2023-02-26T15:53:52.707554Z  INFO fvm::executor::default: is_ethaccount_actor :: false
2023-02-26T15:53:52.707556Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.707558Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.707560Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: false
2023-02-26T15:53:52.707561Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.707563Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.707565Z  INFO fvm::state_tree: Self Balance :: 100000000
2023-02-26T15:53:52.707569Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.707584Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.707596Z TRACE fvm::gas: charging gas: OnCreateActor 2700000.000
2023-02-26T15:53:52.707616Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:52.707618Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:52.707620Z TRACE fvm::call_manager::default: sent 107 -> 407: 0.0
2023-02-26T15:53:52.707628Z  INFO evm_eth_compliance::statetest::executor: Pre Acc 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b
2023-02-26T15:53:52.707632Z  INFO evm_eth_compliance::statetest::executor: Balance :: 17592186044416
2023-02-26T15:53:52.707634Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-26T15:53:52.707636Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 8
2023-02-26T15:53:52.707647Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: true
2023-02-26T15:53:52.707649Z  INFO fvm::executor::default: is_account_actor :: true
2023-02-26T15:53:52.707650Z  INFO fvm::executor::default: is_ethaccount_actor :: false
2023-02-26T15:53:52.707652Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.707653Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.707655Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: false
2023-02-26T15:53:52.707657Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.707659Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.707660Z  INFO fvm::state_tree: Self Balance :: 100000000
2023-02-26T15:53:52.707663Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.707674Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.707685Z TRACE fvm::gas: charging gas: OnCreateActor 2700000.000
2023-02-26T15:53:52.707706Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:52.707708Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:52.707710Z TRACE fvm::call_manager::default: sent 108 -> 408: 0.0
2023-02-26T15:53:52.707716Z  INFO evm_eth_compliance::statetest::executor: Pre Acc 0xb94f5374fce5edbc8e2a8697c15331677e6ebf0b
2023-02-26T15:53:52.707719Z  INFO evm_eth_compliance::statetest::executor: Balance :: 0
2023-02-26T15:53:52.707720Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-26T15:53:52.707723Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-26T15:53:52.707725Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "push0"::Merge::0
2023-02-26T15:53:52.707728Z  INFO evm_eth_compliance::statetest::executor: Path : "mod-push0.json"
2023-02-26T15:53:52.707730Z  INFO evm_eth_compliance::statetest::executor: TX len : 20
2023-02-26T15:53:52.707732Z  INFO evm_eth_compliance::statetest::executor: Sender :: 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b Address {
    payload: ID(
        407,
    ),
}
2023-02-26T15:53:52.707737Z  INFO fvm::executor::default: Stg-01 :: sender_is_valid :: false
2023-02-26T15:53:52.707739Z  INFO fvm::executor::default: is_account_actor :: false
2023-02-26T15:53:52.707741Z  INFO fvm::executor::default: is_ethaccount_actor :: true
2023-02-26T15:53:52.707742Z  INFO fvm::executor::default: is_placeholder_actor :: false
2023-02-26T15:53:52.707744Z  INFO fvm::executor::default:  sequence == 0 :: true
2023-02-26T15:53:52.707746Z  INFO fvm::executor::default: is EAM_ACTOR_ID :: true
2023-02-26T15:53:52.707748Z  INFO fvm::executor::default: Stg-02 :: sender_is_valid :: true
2023-02-26T15:53:52.707749Z  INFO fvm::executor::default: Stg-03 :: sender_is_valid :: true
2023-02-26T15:53:52.707752Z  INFO fvm::state_tree: Self Balance :: 17592186044416
2023-02-26T15:53:52.707755Z  INFO fvm::state_tree: Deduct Amt :: 0
2023-02-26T15:53:52.707758Z TRACE fvm::gas: charging gas: OnChainMessage 690663.000
2023-02-26T15:53:52.707760Z TRACE fvm::gas: charging gas: OnMethodInvocation 75000.000
2023-02-26T15:53:52.707763Z TRACE fvm::call_manager::default: calling 407 -> 408::3844450837
2023-02-26T15:53:53.041255Z TRACE fvm::gas: charging gas: wasm_memory_init 445644.800
2023-02-26T15:53:53.041338Z TRACE fvm::gas: charging gas: wasm_exec 624.000
2023-02-26T15:53:53.041343Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041345Z TRACE fvm::syscalls::bind: syscall debug::enabled: ok
2023-02-26T15:53:53.041354Z TRACE fvm::gas: charging gas: wasm_exec 652.000
2023-02-26T15:53:53.041357Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041359Z TRACE fvm::gas: charging gas: OnMessageContext 0
2023-02-26T15:53:53.041362Z TRACE fvm::syscalls::bind: syscall vm::message_context: ok
2023-02-26T15:53:53.041365Z TRACE fvm::gas: charging gas: wasm_exec 390.400
2023-02-26T15:53:53.041367Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041369Z TRACE fvm::gas: charging gas: OnBlockStat 0
2023-02-26T15:53:53.041372Z TRACE fvm::syscalls::bind: syscall ipld::block_stat: ok
2023-02-26T15:53:53.041381Z TRACE fvm::gas: charging gas: wasm_exec 4252.000
2023-02-26T15:53:53.041383Z TRACE fvm::gas: charging gas: wasm_memory_grow 26214.400
2023-02-26T15:53:53.041385Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041387Z TRACE fvm::gas: charging gas: OnBlockRead 8.400
2023-02-26T15:53:53.041389Z TRACE fvm::syscalls::bind: syscall ipld::block_read: ok
2023-02-26T15:53:53.041396Z TRACE fvm::gas: charging gas: wasm_exec 21613.600
2023-02-26T15:53:53.041398Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041404Z TRACE fvm::syscalls::bind: syscall self::root: ok
2023-02-26T15:53:53.041407Z TRACE fvm::gas: charging gas: wasm_exec 6151.600
2023-02-26T15:53:53.041410Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041413Z TRACE fvm::gas: charging gas: OnBlockOpenBase 187440.000
2023-02-26T15:53:53.041416Z TRACE fvm::gas: charging gas: OnBlockOpenPerByte 1230.000
2023-02-26T15:53:53.041419Z TRACE fvm::syscalls::bind: syscall ipld::block_open: ok
2023-02-26T15:53:53.041420Z TRACE fvm::gas: charging gas: wasm_exec 1124.000
2023-02-26T15:53:53.041422Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041424Z TRACE fvm::gas: charging gas: OnBlockRead 49.200
2023-02-26T15:53:53.041427Z TRACE fvm::syscalls::bind: syscall ipld::block_read: ok
2023-02-26T15:53:53.041434Z TRACE fvm::gas: charging gas: wasm_exec 20973.200
2023-02-26T15:53:53.041436Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041438Z TRACE fvm::gas: charging gas: OnBlockOpenBase 187440.000
2023-02-26T15:53:53.041440Z TRACE fvm::gas: charging gas: OnBlockOpenPerByte 30.000
2023-02-26T15:53:53.041442Z TRACE fvm::syscalls::bind: syscall ipld::block_open: ok
2023-02-26T15:53:53.041444Z TRACE fvm::gas: charging gas: wasm_exec 1460.000
2023-02-26T15:53:53.041446Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041448Z TRACE fvm::gas: charging gas: OnBlockRead 1.200
2023-02-26T15:53:53.041450Z TRACE fvm::syscalls::bind: syscall ipld::block_read: ok
2023-02-26T15:53:53.041456Z TRACE fvm::gas: charging gas: wasm_exec 12660.400
2023-02-26T15:53:53.041458Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041460Z TRACE fvm::gas: charging gas: OnLookupAddress 0
2023-02-26T15:53:53.041464Z TRACE fvm::syscalls::bind: syscall actor::lookup_delegated_address: ok
2023-02-26T15:53:53.041467Z TRACE fvm::gas: charging gas: wasm_exec 4091.600
2023-02-26T15:53:53.041469Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041471Z TRACE fvm::gas: charging gas: OnBlockOpenBase 187440.000
2023-02-26T15:53:53.041473Z TRACE fvm::gas: charging gas: OnBlockOpenPerByte 290.000
2023-02-26T15:53:53.041475Z TRACE fvm::syscalls::bind: syscall ipld::block_open: ok
2023-02-26T15:53:53.041477Z TRACE fvm::gas: charging gas: wasm_exec 1124.000
2023-02-26T15:53:53.041479Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041481Z TRACE fvm::gas: charging gas: OnBlockRead 11.600
2023-02-26T15:53:53.041483Z TRACE fvm::syscalls::bind: syscall ipld::block_read: ok
2023-02-26T15:53:53.041486Z TRACE fvm::gas: charging gas: wasm_exec 5686.000
2023-02-26T15:53:53.041488Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041490Z TRACE fvm::gas: charging gas: OnLookupAddress 0
2023-02-26T15:53:53.041493Z TRACE fvm::syscalls::bind: syscall actor::lookup_delegated_address: ok
2023-02-26T15:53:53.041506Z TRACE fvm::gas: charging gas: wasm_exec 20919.200
2023-02-26T15:53:53.041508Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041510Z TRACE fvm::syscalls::bind: syscall gas::available: ok
2023-02-26T15:53:53.041515Z TRACE fvm::gas: charging gas: wasm_exec 20160.400
2023-02-26T15:53:53.041517Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041526Z TRACE fvm::gas: charging gas: OnResolveAddress 0
2023-02-26T15:53:53.041531Z TRACE fvm::gas: charging gas: OnActorLookup 500000.000
2023-02-26T15:53:53.041533Z TRACE fvm::gas: gas limit reached
2023-02-26T15:53:53.041537Z TRACE fvm::syscalls::bind: syscall send::send: ok
2023-02-26T15:53:53.041550Z TRACE fvm::gas: charging gas: wasm_exec 33106.800
2023-02-26T15:53:53.041552Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041554Z TRACE fvm::gas: charging gas: OnBlockCreate 130.000
2023-02-26T15:53:53.041557Z TRACE fvm::syscalls::bind: syscall ipld::block_create: ok
2023-02-26T15:53:53.041560Z TRACE fvm::gas: charging gas: wasm_exec 152.000
2023-02-26T15:53:53.041562Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041565Z TRACE fvm::gas: charging gas: OnBlockLink 549581.200
2023-02-26T15:53:53.041570Z TRACE fvm::syscalls::bind: syscall ipld::block_link: ok
2023-02-26T15:53:53.041577Z TRACE fvm::gas: charging gas: wasm_exec 45031.200
2023-02-26T15:53:53.041579Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041581Z TRACE fvm::gas: charging gas: OnBlockCreate 1230.000
2023-02-26T15:53:53.041583Z TRACE fvm::syscalls::bind: syscall ipld::block_create: ok
2023-02-26T15:53:53.041585Z TRACE fvm::gas: charging gas: wasm_exec 152.000
2023-02-26T15:53:53.041587Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041589Z TRACE fvm::gas: charging gas: OnBlockLink 918345.200
2023-02-26T15:53:53.041591Z TRACE fvm::syscalls::bind: syscall ipld::block_link: ok
2023-02-26T15:53:53.041594Z TRACE fvm::gas: charging gas: wasm_exec 7462.800
2023-02-26T15:53:53.041596Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041598Z TRACE fvm::gas: charging gas: OnActorUpdate 475000.000
2023-02-26T15:53:53.041601Z TRACE fvm::syscalls::bind: syscall self::set_root: ok
2023-02-26T15:53:53.041605Z TRACE fvm::gas: charging gas: wasm_exec 14390.400
2023-02-26T15:53:53.041607Z TRACE fvm::gas: charging gas: OnSyscall 14000.000
2023-02-26T15:53:53.041609Z TRACE fvm::gas: charging gas: OnBlockCreate 10.000
2023-02-26T15:53:53.041611Z TRACE fvm::syscalls::bind: syscall ipld::block_create: ok
2023-02-26T15:53:53.041614Z TRACE fvm::gas: charging gas: wasm_exec 4564.000
2023-02-26T15:53:53.041637Z TRACE fvm::call_manager::default: returning 408::3844450837 -> 407 (0)
2023-02-26T15:53:53.041641Z TRACE fvm::gas: charging gas: OnChainReturnValue 1300.000
2023-02-26T15:53:53.041654Z  INFO evm_eth_compliance::statetest::executor: Post Hash Check ::
2023-02-26T15:53:53.041657Z  INFO evm_eth_compliance::statetest::executor: State info for => "a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
2023-02-26T15:53:53.041668Z  INFO evm_eth_compliance::common::tester: nonce :: 1
2023-02-26T15:53:53.041673Z  INFO evm_eth_compliance::common::tester: balance :: 17592186044416
2023-02-26T15:53:53.041681Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-26T15:53:53.041684Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
2023-02-26T15:53:53.041687Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000300"
2023-02-26T15:53:53.041690Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-26T15:53:53.041691Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-26T15:53:53.041693Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-26T15:53:53.041695Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: cc61b581b699b895ad2557e2aa9578bcf05d163d6c03a900a38e312bdfc2f79b
2023-02-26T15:53:53.041697Z  INFO evm_eth_compliance::statetest::executor: State info for => "b94f5374fce5edbc8e2a8697c15331677e6ebf0b"
2023-02-26T15:53:53.041702Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-26T15:53:53.041703Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-26T15:53:53.041710Z  INFO evm_eth_compliance::common::tester: slots :: [
    (
        0x0000000000000000000000000000000000000000000000000000000000000001,
        b"\x01",
    ),
]
2023-02-26T15:53:53.041716Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: af75e120bc9b2b813d81494fcb57703dcd277a3dab4cefbfb6e8188c8c101d6b
2023-02-26T15:53:53.041718Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000600"
2023-02-26T15:53:53.041721Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-26T15:53:53.041722Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-26T15:53:53.041725Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-26T15:53:53.041726Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: fd9bdc48c415ec6f74ded272c8758e673376fc007812223384f6eea1588dab60
2023-02-26T15:53:53.041728Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000700"
2023-02-26T15:53:53.041731Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-26T15:53:53.041732Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-26T15:53:53.041734Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-26T15:53:53.041736Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 29c955fec03398c668c9f67fcd2c1d24e301c426a12737ce10c33113443a8410
2023-02-26T15:53:53.041738Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000200"
2023-02-26T15:53:53.041740Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-26T15:53:53.041742Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-26T15:53:53.041744Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-26T15:53:53.041746Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: a44ddbe3846599b1b2ca0594fb0cb0c2d6d63b877ce5ddb234339190f6535058
2023-02-26T15:53:53.041748Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000100"
2023-02-26T15:53:53.041751Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-26T15:53:53.041753Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-26T15:53:53.041756Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-26T15:53:53.041757Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 0125401e1ab3861d0d9dd8099943b70a1fd558be51c551394387321c48cf5d97
2023-02-26T15:53:53.041759Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000400"
2023-02-26T15:53:53.041762Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-26T15:53:53.041764Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-26T15:53:53.041772Z  INFO evm_eth_compliance::common::tester: slots :: [
    (
        0x0000000000000000000000000000000000000000000000000000000000000000,
        b"\n",
    ),
    (
        0x0000000000000000000000000000000000000000000000000000000000000001,
        b"\n",
    ),
]
2023-02-26T15:53:53.041779Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 48191a2b9cc0ce9f46786b06bc6b47348b83d5e37b8bde367268384d07df718b
2023-02-26T15:53:53.041781Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000500"
2023-02-26T15:53:53.041784Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-26T15:53:53.041785Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-26T15:53:53.041787Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-26T15:53:53.041789Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: edcea87ee48aa9a04c103b5b3c70ed9ff9fe2588bd460852de66d194439bd683
2023-02-26T15:53:53.041812Z  INFO evm_eth_compliance::statetest::executor: Calc :: 0xa749ef084d880aee91e425593f6526dddfacea89ad64b01f8c85abafd8dd1fdf
2023-02-26T15:53:53.041815Z  INFO evm_eth_compliance::statetest::executor: Actual :: 0x84893d9a4161a9cf913c9c53a1827b7a3abfa2f0b57216e605b7cb87f527ae72
2023-02-26T15:53:53.041821Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4367801,
    events_root: None,
}
2023-02-26T15:53:53.043046Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-26T15:53:53.043176Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.774625ms
=== Start ===
=== OK Status ===
Count :: 1
{
    "mod-push0.json::push0": [
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
```