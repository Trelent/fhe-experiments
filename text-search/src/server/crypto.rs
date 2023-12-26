use tfhe::{ boolean::prelude::*, Error };

#[derive(Debug)]
pub struct FHEError {
    message: String,
}

impl FHEError {
    pub fn new(message: String) -> Self {
        FHEError { message }
    }
}

impl std::fmt::Display for FHEError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "FHEError: {}", self.message)
    }
}

impl std::error::Error for FHEError {}

impl std::convert::From<Error> for FHEError {
    fn from(err: Error) -> Self {
        FHEError::new(format!("tFHE Error: {:}", err))
    }
}

/// Return a ciphertext that decrypts to `true` if `a` and `b` encrypt the same bit and `false`
/// otherwise.
pub fn bits_are_equal(server_key: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    server_key.xnor(a, b)
}

/// If `a` is not empty and `a` and `b` have the same length, return `Ok(c)` where `c` is ciphertext
/// that decrypts to `true` if `a` and `b` encrypt the same sequence of bits and `false` otherwise.
/// Return an `FHEError` if `a` is empty or if `a` and `b` have different lengths.
pub fn are_equal(
    server_key: &ServerKey,
    a: &[Ciphertext],
    b: &[Ciphertext]
) -> Result<Ciphertext, FHEError> {
    // check that a is not empty
    if a.len() == 0 {
        return Err(
            FHEError::new(
                "Error checking the equality between two elements: the first element is empty".to_string()
            )
        );
    }

    // check that the two inputs have the same size
    if a.len() != b.len() {
        return Err(
            FHEError::new(
                format!(
                    "Error checking the equality between two elements: the elements have different lengths ({} and {})",
                    a.len(),
                    b.len()
                )
            )
        );
    }

    // check the equality of the first elements
    println!("    Checking the equality of the first elements...");
    let mut are_equal = bits_are_equal(server_key, &a[0], &b[0]);
    println!("    Done.");

    // check the equality of the other elements
    for i in 1..a.len() {
        println!("    Checking the equality of the {}th elements...", i);
        are_equal = server_key.and(&are_equal, &bits_are_equal(server_key, &a[i], &b[i]));
        println!("    Done.");
    }

    Ok(are_equal)
}
