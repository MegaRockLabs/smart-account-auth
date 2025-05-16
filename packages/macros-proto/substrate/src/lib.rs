use quote::quote;
use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};


#[proc_macro_attribute]
pub fn saa_type(
    _attr: TokenStream,
    input: TokenStream,
) -> TokenStream {
    let input_ast = parse_macro_input!(input as DeriveInput);
    match &input_ast.data {
        syn::Data::Struct(_) => {
            quote! {
                #[derive(
                    ::std::fmt::Debug,
                    ::std::clone::Clone,
                    ::std::cmp::PartialEq, 
                    ::saa_schema::scale::Encode,
                    ::saa_schema::scale::Decode,
                )]
                #[cfg_attr(feature = "std", derive(::saa_schema::scale_info::TypeInfo))]
                #[allow(clippy::derive_partial_eq_without_eq)]
                #input_ast
            }.into()
        },
        syn::Data::Enum(_) => {
            quote! {
                #[derive(
                    ::std::fmt::Debug,
                    ::std::clone::Clone,
                    ::std::cmp::PartialEq, 
                    ::saa_schema::scale::Encode,
                    ::saa_schema::scale::Decode,
                )]
                #[cfg_attr(feature = "std", derive(::saa_schema::scale_info::TypeInfo))]
                #[allow(clippy::derive_partial_eq_without_eq)]
                #input_ast
            }.into()
        },
        syn::Data::Union(_) => panic!("unions are not supported"),
    }
}



