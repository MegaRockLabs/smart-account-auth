use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{parse_macro_input, parse_quote, AttributeArgs, DataEnum, DeriveInput};


fn session_merger(metadata: TokenStream, left: TokenStream, right: TokenStream) -> TokenStream {
    use syn::Data::Enum;

    // parse metadata
    let args = parse_macro_input!(metadata as AttributeArgs);
    if let Some(first_arg) = args.first() {
        return syn::Error::new_spanned(first_arg, "macro takes no arguments")
            .to_compile_error()
            .into();
    }

    // parse the left enum
    let mut left: DeriveInput = parse_macro_input!(left);

    let Enum(DataEnum {
        variants,
        ..
    }) = &mut left.data else {
        return syn::Error::new(left.ident.span(), "only enums can accept variants")
            .to_compile_error()
            .into();
    };

    // parse the right enum
    let right: DeriveInput = parse_macro_input!(right);
    let Enum(DataEnum {
        variants: to_add,
        ..
    }) = right.data else {
        return syn::Error::new(left.ident.span(), "only enums can provide variants")
            .to_compile_error()
            .into();
    };

    // insert variants from the right to the left
    variants.extend(to_add.into_iter());

    //quote! { #left }.into()


    // also derived Clone and Debug


    quote! { 
        #[derive(
            ::saa_schema::strum_macros::Display, 
            ::saa_schema::strum_macros::EnumDiscriminants
        )]
        #[strum_discriminants(
            name(ExecuteMsgNames),
            derive(
                ::saa_schema::strum_macros::Display,
                ::saa_schema::strum_macros::EnumString,
                ::saa_schema::strum_macros::AsRefStr
            ),
            strum(serialize_all = "snake_case", crate = "::saa_schema::strum")
        )]
        #[strum(serialize_all = "snake_case", crate = "::saa_schema::strum")]
        #left 
    }.into()
}




#[proc_macro_attribute]
pub fn session_action(metadata: TokenStream, input: TokenStream) -> TokenStream {
    session_merger(
        metadata,
        input,
        quote! {
            enum Right {
                CreateSession(::smart_account_auth::messages::CreateSession),

                #[cfg(feature = "wasm")]
                CreateSessionFromMsg(::smart_account_auth::messages::CreateSessionFromMsg<Box<Self>>),

                WithSessionKey(::smart_account_auth::messages::WithSessionMsg<Box<Self>>),

                RevokeSession(::smart_account_auth::messages::RevokeKeyMsg)
            }
        }
        .into(),
    )
}




#[proc_macro_attribute]
pub fn wasm_serde(
    _attr: TokenStream,
    input: TokenStream,
) -> TokenStream {
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
            #[cfg_attr(all(feature = "substrate", not(feature="cosmwasm")), derive(
                ::saa_schema::scale::Encode, 
                ::saa_schema::scale::Decode
            ))]
            #[cfg_attr(all(feature = "solana", not(feature="cosmwasm")), derive(
                ::saa_schema::borsh::BorshSerialize, 
                ::saa_schema::borsh::BorshDeserialize
            ))]
            #[cfg_attr(all(feature = "std", feature="substrate", not(feature="cosmwasm")), derive(
                ::saa_schema::scale_info::TypeInfo)
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
            #[cfg_attr(all(feature = "solana", not(feature="cosmwasm")), derive(
                ::saa_schema::borsh::BorshSerialize, 
                ::saa_schema::borsh::BorshDeserialize
            ))]
            #[cfg_attr(all(feature = "substrate", not(feature="cosmwasm")), derive(
                ::saa_schema::scale::Encode, 
                ::saa_schema::scale::Decode
            ))]
            #[cfg_attr(all(feature = "std", feature="substrate", not(feature="cosmwasm")), 
                derive(::saa_schema::scale_info::TypeInfo)
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