use pabs_crf::keygen::KeyGen;
use pabs_crf::setup::Setup;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;
use pabs_crf::{PabsCrfResult, Policy};

fn main() -> PabsCrfResult<()> {
    let setup = Setup::new();
    let keygen = KeyGen::new();

    let (public_parameters, master_secret_key) = setup.try_generate_structured(128)?;
    let user_secret_key = keygen.try_generate_structured(
        &public_parameters,
        &master_secret_key,
        &["admin", "finance"],
    )?;

    let policy = Policy::parse("admin AND finance")?;
    let message = b"PABS-CRF research artifact";
    let signature = sign_structured(&user_secret_key, message, &policy, 0)?;

    assert!(verify_signature_struct(
        &public_parameters,
        message,
        &policy,
        &signature,
    )?);

    println!("PABS-CRF signature verified successfully.");
    Ok(())
}
