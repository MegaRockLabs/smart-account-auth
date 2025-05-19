mod utils;
use quote::{ToTokens, quote};
use proc_macro::TokenStream;
use syn::{parse_macro_input, parse_quote, AttributeArgs, DeriveInput, Meta, MetaList, NestedMeta};
use utils::{fallible_macro, Options};


fn strum_enum(input: &DeriveInput, attr_args: &[NestedMeta]) -> proc_macro2::TokenStream {
    // Extract optional name(...) argument
    let name_arg = attr_args.iter().find_map(|meta| {
        if let NestedMeta::Meta(Meta::List(MetaList { path, nested, .. })) = meta {
            if path.is_ident("name") {
                return Some(quote! { name(#nested) });
            }
        }
        None
    });

    let maybe_name = if let Some(name) = name_arg {
        quote! { #name, }
    } else {
        quote! {}
    };
    
    let ident = &input.ident;
    quote! {
        #[derive(
            Clone, Debug, PartialEq,
            ::saa_schema::strum_macros::Display,
            ::saa_schema::strum_macros::EnumDiscriminants,
            ::saa_schema::strum_macros::VariantNames
        )]
        #[strum_discriminants(
            #maybe_name
            derive(
                ::saa_schema::strum_macros::Display,
                ::saa_schema::strum_macros::EnumString,
                ::saa_schema::strum_macros::VariantArray,
                ::saa_schema::strum_macros::AsRefStr
            ),
            strum(serialize_all = "snake_case", crate = "::saa_schema::strum")
        )]
        #[strum(serialize_all = "snake_case", crate = "::saa_schema::strum")]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #input

        impl ::saa_schema::strum::IntoDiscriminant for Box<#ident> {
            type Discriminant = <#ident as ::saa_schema::strum::IntoDiscriminant>::Discriminant;
            fn discriminant(&self) -> Self::Discriminant {
                (*self).discriminant()
            }
        }
    }
}




#[proc_macro_attribute]
pub fn saa_type(
    _attr: TokenStream,
    input: TokenStream,
) -> TokenStream {
    let input_ast = parse_macro_input!(input as DeriveInput);
    match &input_ast.data {
        syn::Data::Struct(_) => {
            quote! {
                #[derive(Clone, Debug, PartialEq)]
                #[allow(clippy::derive_partial_eq_without_eq)]
                #input_ast
            }.into()
        },
        syn::Data::Enum(_) => {
            quote! {
                #[derive(Clone, Debug, PartialEq)]
                #[allow(clippy::derive_partial_eq_without_eq)]
                #input_ast
            }.into()
        },
        syn::Data::Union(_) => panic!("unions are not supported"),
    }
}



fallible_macro! {
    #[proc_macro_attribute]
    pub fn saa_error(
        attr: proc_macro::TokenStream,
        input: proc_macro::TokenStream,
    ) -> syn::Result<proc_macro::TokenStream> {
        let options = syn::parse(attr)?;
        let input = syn::parse(input)?;
        let expanded = saa_error_impl(input, options)?;
        Ok(expanded.into_token_stream().into())
    }
}



fn saa_error_impl(input: DeriveInput, options: Options) -> syn::Result<DeriveInput> {
    let crate_path = &options.crate_path;
    let error_path: syn::Path = syn::parse_quote!(#crate_path::thiserror::Error);
    let mut stream = quote! {
        #[derive(PartialEq, Debug, #error_path)]
    };
    match &input.data {
        syn::Data::Enum(_) => {},
        _ => return Err(syn::Error::new_spanned(&input, "Only enums are supported")),
    };
    stream.extend(input.to_token_stream());
    syn::parse2(stream)
}



/* #[proc_macro_attribute]
pub fn saa_derivable(
    attr: TokenStream,
    input: TokenStream,
) -> TokenStream {
    let attr_args = parse_macro_input!(attr as AttributeArgs);
    let input_ast = parse_macro_input!(input as DeriveInput);
    match &input_ast.data {
        syn::Data::Struct(_) => {
            quote! {
                #[derive(
                    Debug,
                    Clone,
                    PartialEq,
                    ::saa_schema::serde::Serialize,
                    ::saa_schema::serde::Deserialize,
                    ::saa_schema::schemars::JsonSchema
                )]
                #[allow(clippy::derive_partial_eq_without_eq)]
                #input_ast
            }
            .into()
        }
        syn::Data::Enum(_) => {
            strum_enum(&input_ast, &attr_args).into()
        }
        syn::Data::Union(_) => panic!("unions are not supported"),
    }
}
 */
#[proc_macro_attribute]
pub fn saa_derivable(
    attr: TokenStream,
    input: TokenStream,
) -> TokenStream {
    let attr_args = parse_macro_input!(attr as AttributeArgs);
    let input_ast = parse_macro_input!(input as DeriveInput);
    match &input_ast.data {
        syn::Data::Struct(_) => {
            quote! {
                #[derive(Clone, Debug, PartialEq)]
                #[allow(clippy::derive_partial_eq_without_eq)]
                #input_ast
            }.into()
        },
        syn::Data::Enum(_) => {
            strum_enum(&input_ast, &attr_args).into()
        },
        syn::Data::Union(_) => panic!("unions are not supported"),
    }
}




#[proc_macro_attribute]
pub fn saa_str_struct(
    _attr: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let expanded : DeriveInput = match input.data {
        syn::Data::Struct(_) => parse_quote! {
            #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
            #input 
        },
        syn::Data::Enum(_) => panic!("enums are not supported"),
        syn::Data::Union(_) => panic!("unions are not supported"),
    };

    let stream = expanded.into_token_stream();

    proc_macro::TokenStream::from(stream)
}