use quote::ToTokens;
use syn::{parse_quote, parse_macro_input, DeriveInput};


#[proc_macro_attribute]
pub fn wasm_serde(
    _attr: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let expanded : DeriveInput = match input.data {
        syn::Data::Struct(_) => parse_quote! {
            #[derive(
                Clone,
                Debug,
                PartialEq
            )]
            #[cfg_attr(any(feature = "cosmwasm", feature = "wasm"),
                derive(
                    ::saa_schema::serde::Serialize,
                    ::saa_schema::serde::Deserialize,
                    ::saa_schema::schemars::JsonSchema
                ),
                serde(deny_unknown_fields, crate = "::saa_schema::serde"),
                schemars(crate = "::saa_schema::schemars")
            )]
            #[cfg_attr(feature = "substrate", derive(
                ::saa_schema::scale::Encode, 
                ::saa_schema::scale::Decode
            ))]
            #[cfg_attr(feature = "solana", derive(
                ::saa_schema::borsh::BorshSerialize, 
                ::saa_schema::borsh::BorshDeserialize
            ))]
            #[cfg_attr(all(feature = "std", feature="substrate"), derive(
                saa_schema::scale_info::TypeInfo)
            )]
            #[allow(clippy::derive_partial_eq_without_eq)]
            #input 
        },
        syn::Data::Enum(_) => parse_quote! {
            #[derive(
                Clone,
                Debug,
                PartialEq
            )]
            #[cfg_attr(any(feature = "cosmwasm", feature = "wasm"),
                derive(
                    ::saa_schema::serde::Serialize,
                    ::saa_schema::serde::Deserialize,
                    ::saa_schema::schemars::JsonSchema
                ),
                serde(deny_unknown_fields, rename_all = "snake_case", crate = "::saa_schema::serde"),
                schemars(crate = "::saa_schema::schemars")
            )]
            #[cfg_attr(feature = "solana", derive(
                ::saa_schema::borsh::BorshSerialize, 
                ::saa_schema::borsh::BorshDeserialize
            ))]
            #[cfg_attr(feature = "substrate", derive(
                ::saa_schema::scale::Encode, 
                ::saa_schema::scale::Decode
            ))]
            #[cfg_attr(all(feature = "std", feature = "substrate"), derive(
                saa_schema::scale_info::TypeInfo)
            )]
            #[allow(clippy::derive_partial_eq_without_eq)]
            #input 
        },
        syn::Data::Union(_) => panic!("unions are not supported"),
    };

    let stream = expanded.into_token_stream();

    proc_macro::TokenStream::from(stream)
}




#[proc_macro_attribute]
pub fn wasm_string_struct(
    _attr: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let expanded : DeriveInput = match input.data {
        syn::Data::Struct(_) => parse_quote! {
            #[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
            #[cfg_attr(any(feature = "cosmwasm", feature = "wasm"),
                derive(::saa_schema::schemars::JsonSchema),
                serde(deny_unknown_fields, crate = "::saa_schema::serde"),
            )]
            #[cfg_attr(feature = "substrate", derive(
                ::saa_schema::scale::Encode, 
                ::saa_schema::scale::Decode
            ))]
            #[cfg_attr(feature = "solana", derive(
                ::saa_schema::borsh::BorshSerialize, 
                ::saa_schema::borsh::BorshDeserialize
            ))]
            #[cfg_attr(all(feature = "std", feature="substrate"), derive(
                saa_schema::scale_info::TypeInfo)
            )]
            #[allow(clippy::derive_partial_eq_without_eq)]
            #input 
        },
        syn::Data::Enum(_) => panic!("enums are not supported"),
        syn::Data::Union(_) => panic!("unions are not supported"),
    };

    let stream = expanded.into_token_stream();

    proc_macro::TokenStream::from(stream)
}