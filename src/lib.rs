use argon2::{password_hash::rand_core, Argon2, Params, Version};
use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use rand_core::{OsRng, RngCore};
use sha3::{Digest, Sha3_256};

fn into_scalar(hash: &[u8]) -> Scalar {
    Scalar::from_uint_reduced(U256::from_le_slice(hash))
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn sha3_256(master_pwd: &str) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(master_pwd.as_bytes());
    hasher.finalize().to_vec()
}

fn hash_to_curve(master_pwd: &str) -> ProjectivePoint {
    let hash = sha3_256(master_pwd);
    let scalar_hash = into_scalar(&hash);
    AffinePoint::GENERATOR * scalar_hash
}

fn argon2(master_pwd: String, point: ProjectivePoint) -> [u8; 32] {
    let params = Params::new(1024, 1, 1, None).unwrap();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2i, Version::default(), params);

    let point = point.to_encoded_point(false).as_bytes().to_owned();
    let mut buf = [0u8; 32];
    argon2
        .hash_password_into(
            &[master_pwd.as_bytes(), &point].concat(),
            &sha3_256(""),
            &mut buf,
        )
        .unwrap();
    buf
}

pub fn generate_password(master_password: String) -> [u8; 32] {
    let point = hash_to_curve(&master_password);
    let blind = into_scalar(&random_bytes());
    let alpha = point * blind;
    let beta = to_server(alpha);
    let rec = blind.invert().unwrap();
    let rwd = beta * rec;
    argon2(master_password, rwd)
}

fn to_server(alpha: ProjectivePoint) -> ProjectivePoint {
    // simulate server behavior
    let k = into_scalar(&random_bytes());
    alpha * k
}
