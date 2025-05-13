use quote::{ToTokens, quote};
use proc_macro::TokenStream;
use syn::{parse_macro_input, parse_quote, AttributeArgs, DataEnum, DeriveInput};



fn merge_enum_variants(
    metadata: TokenStream,
    left_ts: TokenStream,
    right_ts: TokenStream,
) -> TokenStream {
    use syn::Data::Enum;

    // Parse metadata and check no args
    let args = parse_macro_input!(metadata as AttributeArgs);
    if let Some(first_arg) = args.first() {
        return syn::Error::new_spanned(first_arg, "macro takes no arguments")
            .to_compile_error()
            .into();
    }

    // Parse left and ensure it's enum
    let mut left: DeriveInput = parse_macro_input!(left_ts);
    let Enum(DataEnum { variants, .. }) = &mut left.data else {
        return syn::Error::new(left.ident.span(), "only enums can accept variants")
            .to_compile_error()
            .into();
    };

    // Parse right and ensure it's enum
    let right: DeriveInput = parse_macro_input!(right_ts);
    let Enum(DataEnum { variants: to_add, .. }) = right.data else {
        return syn::Error::new(left.ident.span(), "only enums can provide variants")
            .to_compile_error()
            .into();
    };

    // Merge variants
    variants.extend(to_add.into_iter());

    // Return modified left
    left.into_token_stream().into()
}



fn generate_session_macro<F>(
    metadata: TokenStream,
    input: TokenStream,
    right_enum: TokenStream,
    extra_impl: F,
) -> TokenStream
where
    F: Fn(&syn::Ident) -> proc_macro2::TokenStream,
{
    let merged = merge_enum_variants(metadata, input, right_enum);
    // Try to parse the merged stream back into DeriveInput
    let parsed: DeriveInput = match syn::parse(merged.clone()) {
        Ok(val) => val,
        Err(err) => return err.to_compile_error().into(), // This is a valid return
    };
    let enum_name = &parsed.ident;
    let common_impl = quote! {

        #[derive(
            ::saa_schema::strum_macros::Display, 
            ::saa_schema::strum_macros::EnumDiscriminants,
            ::saa_schema::strum_macros::VariantNames,
        )]
        #[strum_discriminants(
            derive(
                ::saa_schema::strum_macros::Display,
                ::saa_schema::strum_macros::EnumString,
                ::saa_schema::strum_macros::VariantArray,
                ::saa_schema::strum_macros::AsRefStr
            ),
            strum(serialize_all = "snake_case", crate = "::saa_schema::strum")
        )]
        #[strum(serialize_all = "snake_case", crate = "::saa_schema::strum")]
        #parsed

        impl ::saa_schema::strum::IntoDiscriminant for Box<#enum_name> {
            type Discriminant = <#enum_name as ::saa_schema::strum::IntoDiscriminant>::Discriminant;
            fn discriminant(&self) -> Self::Discriminant {
                (*self).discriminant()
            }
        }
    };
    let custom_impl = extra_impl(enum_name);

    quote! {
        #common_impl
        #custom_impl
    }
    .into()
}



#[proc_macro_attribute]
pub fn session_action(metadata: TokenStream, input: TokenStream) -> TokenStream {
    generate_session_macro(
        metadata,
        input,
        quote! {
            enum Right {
                SessionActions(Box<::smart_account_auth::msgs::SessionActionMsg<Self>>),
            }
        }
        .into(),
        |enum_name| {
            quote! {
                impl ::smart_account_auth::msgs::SessionActionsMatch for #enum_name {
                    fn match_actions(&self) -> Option<::smart_account_auth::msgs::SessionActionMsg<Self>> {
                        match self {
                            Self::SessionActions(msg) => Some((**msg).clone()),
                            _ => None,
                        }
                    }
                }
            }
        },
    )
}



#[proc_macro_attribute]
pub fn session_query(metadata: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(metadata as AttributeArgs);

    // Ensure exactly one argument
    if args.len() != 1 {
        return syn::Error::new_spanned(
            quote! { #[session_query(..)] },
            "expected #[session_query(ExecuteMsg)] with exactly one argument",
        )
        .to_compile_error()
        .into();
    }

    // Extract identifier (e.g., ExecuteMsg)
    let base_msg_ident = match &args[0] {
        syn::NestedMeta::Meta(syn::Meta::Path(path)) => match path.get_ident() {
            Some(ident) => ident.clone(),
            None => {
                return syn::Error::new_spanned(
                    path,
                    "expected identifier like `ExecuteMsg`"
                )
                .to_compile_error()
                .into();
            }
        },
        other => {
            return syn::Error::new_spanned(
                other,
                "expected identifier like `ExecuteMsg`"
            )
            .to_compile_error()
            .into();
        }
    };


    // Proceed as before
    generate_session_macro(
        TokenStream::new(), // no extra args needed downstream
        input,
        quote! {
            enum Right {
                SessionQueries(Box<::smart_account_auth::msgs::SessionQueryMsg<Self>>),
            }
        }
        .into(),
        move |enum_name| {
            quote! {
                impl ::smart_account_auth::msgs::SessionQueriesMatch for #enum_name {
                    fn match_queries(&self) -> Option<::smart_account_auth::msgs::SessionQueryMsg<Self>> {
                        match self {
                            Self::SessionQueries(msg) => Some((**msg).clone()),
                            _ => None,
                        }
                    }
                }

                impl ::smart_account_auth::msgs::QueryUsesActions for #enum_name {
                    type ActionMsg = #base_msg_ident;
                }
            }
        },
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
                ::saa_schema::scale_info::TypeInfo)
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