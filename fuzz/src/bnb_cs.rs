use honggfuzz::fuzz;
use bdk::testutils;
use bdk::bitcoin;
use bdk::FeeRate;
use bdk::wallet::Wallet;
use bdk::database::MemoryDatabase;

use bitcoin::util::address::WitnessVersion;
use bitcoin::Script;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    fee_rate: f32,
    inputs: Vec<u64>,
    recipients: Vec<u64>,
}

fn main() {
    let descriptors = ("wpkh(02b511bd5771e47ee27558b1765e87b541668304ec567721c7b880edc0a010da55)", None::<String>);

    loop {
        fuzz!(|data: FuzzData| {
            if data.inputs.len() > 127 || data.inputs.iter().any(|v| *v > 1_000_000) {
                return;
            }

            let mut database = MemoryDatabase::new();

            let mut balance = 0;
            for (i, val) in data.inputs.iter().enumerate() {
                let tx_meta = testutils! {
                    @tx ( (@external descriptors, 0) => *val ) ( @inputs (Default::default(), i as u32) ) (@confirmations 1)
                };
                bdk::populate_test_db!(&mut database, tx_meta, Some(100));
                balance += val;
            }

            if !data.fee_rate.is_normal() || data.fee_rate <= 0.0 || data.fee_rate > 1e5 || data.recipients.len() > 33_000 || data.recipients.iter().any(|v| *v > 100_000) {
                return;
            }

            let total_out = data.recipients.iter().sum::<u64>();
            if total_out > balance {
                return;
            }

            dbg!(&data);

            let wallet = Wallet::new(descriptors.0, None, bitcoin::Network::Regtest, database).unwrap();
            let _address = wallet.get_address(bdk::wallet::AddressIndex::New).unwrap(); // cache scripts

            let segwit_script = Script::new_witness_program(WitnessVersion::V0, &[0_u8; 20]);

            let (psbt, details) = {
                let mut builder = wallet
                    .build_tx()
                    .coin_selection(bdk::wallet::coin_selection::BranchAndBoundCoinSelection::new(10));
                builder
                    .only_witness_utxo()
                    .fee_rate(FeeRate::from_sat_per_vb(data.fee_rate));

                for amount in data.recipients {
                    builder.add_recipient(segwit_script.clone(), amount);
                }

                match builder.finish() {
                    Ok(v) => v,
                    Err(_) => return,
                }
            };

            let input_sum = psbt.inputs.iter().map(|i| i.witness_utxo.as_ref().unwrap().value).sum::<u64>();
            let output_sum = psbt.unsigned_tx.output.iter().map(|o| o.value).sum::<u64>();
            let fee = details.fee.unwrap();

            dbg!(&psbt, &details);

            let mut tx = psbt.extract_tx();
            for txin in &mut tx.input {
                txin.witness.push([0x00; 108]); // fake signature
            }

            assert_eq!(details.sent, input_sum);
            assert_eq!(details.received, input_sum - total_out - fee);
            assert_eq!(details.received + total_out, output_sum);

            let fee_rate = fee as f32 / (tx.weight() as f32 / 4.0);
            dbg!(fee_rate, data.fee_rate);

            assert!(fee_rate >= data.fee_rate);
            if details.received > 0 {
                assert!(fee_rate <= data.fee_rate + 1.0);
            }
        });
    }
}
