mod client;
mod server;

use tfhe::boolean::prelude::*;
use client::operations::{ split_and_pad_str, str_to_encrypted_seq, pad_word };
use server::search::search;

fn main() {
    // Get Keys
    let (client_key, server_key) = gen_keys();

    // Search term
    println!("Encrypting search term...");
    let word = "world";
    let max_length = word.len();
    let encrypted_word = str_to_encrypted_seq(&client_key, word);
    println!("Done.");

    // Document
    println!("Encrypting document...");
    let doc = "Hello, world";
    let list_words = split_and_pad_str(doc, max_length);
    let words_enc = list_words
        .iter()
        .map(|x| str_to_encrypted_seq(&client_key, &pad_word(x, max_length)))
        .collect::<Vec<Vec<Ciphertext>>>();
    println!("Done.");

    // TODO: Add code to initialize server_key, word, and list
    // Then call the search function with these parameters
    println!("Searching on the server...");
    let result = search(&server_key, &encrypted_word, &words_enc);
    match result {
        Ok(result) => println!("Search result: {:?}", client_key.decrypt(&result)),
        Err(err) => println!("Error: {}", err),
    }
}
