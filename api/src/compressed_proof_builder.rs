use std::sync::Arc;

use nova_scotia::S;

use nova_snark::traits::Group;
use nova_snark::{CompressedSNARK, PublicParams, RecursiveSNARK};
use tokio::time::Instant;

use tokio::sync::mpsc::Receiver;
use tracing::debug;

use crate::ivc_proof_folder::NUM_FOLDS;
use crate::{C1, C2, G1, G2};

pub struct CompressedProofBuilder {
    rx: Receiver<RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>>,
    pp: Arc<PublicParams<G1, G2, C1<G1>, C2<G2>>>,
    start_public_input: Vec<<G1 as Group>::Scalar>,
}
impl CompressedProofBuilder {
    pub fn new(
        rx: Receiver<RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>>,
        pp: Arc<PublicParams<G1, G2, C1<G1>, C2<G2>>>,
        start_public_input: Vec<<G1 as Group>::Scalar>,
    ) -> Self {
        //, tx: Sender<Vec<T>>) -> Self {
        Self {
            rx,
            pp, // tx,
            start_public_input,
            // accumulator: Vec::with_capacity(UPDATE_LEN),
        }
    }
    pub async fn run(&mut self) {
        debug!("CompressedProofBuilder started");
        let (pk, vk) =
            CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(self.pp.as_ref()).unwrap();
        let mut counter = 1;
        let z0_secondary = vec![<G2 as Group>::Scalar::zero()];
        while let Some(update) = self.rx.recv().await {
            let recursive_snark = update;
            let start = Instant::now();

            let compressed_snark = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(
                self.pp.as_ref(),
                &pk,
                &recursive_snark,
            )
            .unwrap();
            let duration = start.elapsed();
            debug!("compressed snark proof time {:?}", duration);
            debug!(
                "compressed snark proof size {:.2} Mb",
                serde_json::to_string(&compressed_snark).unwrap().len() as f64 / 1_000_000.0
            );
            let start = Instant::now();
            let res = compressed_snark.verify(
                &vk,
                counter * NUM_FOLDS,
                self.start_public_input.clone(),
                z0_secondary.clone(),
            );
            debug!(
                "CompressedSNARK::verify: {:?}, took {:?}",
                res.is_ok(),
                start.elapsed()
            );
            counter += 1;
        }
    }
}
