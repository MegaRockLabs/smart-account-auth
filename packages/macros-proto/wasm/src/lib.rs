use quote::{quote, ToTokens};
use proc_macro::TokenStream;
use syn::{parse_macro_input, parse_quote, AttributeArgs, DeriveInput, Meta, MetaList, NestedMeta};
use utils::{fallible_macro, Options};

mod utils;


fallible_macro! {
    #[proc_macro_attribute]
    pub fn saa_type(
        attr: proc_macro::TokenStream,
        input: proc_macro::TokenStream,
    ) -> syn::Result<proc_macro::TokenStream> {
        let options = syn::parse(attr)?;
        let expanded = saa_type_impl(input, options);
        Ok(expanded)
    }
}


fn saa_type_impl(input: TokenStream, options: Options) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let serde_args = if options.no_deny {
        vec![
            quote! { crate = "::saa_schema::serde" },
        ]
    } else {
        vec![
            quote! { deny_unknown_fields, crate = "::saa_schema::serde" },
        ]
    };

    match &input.data {
        syn::Data::Struct(_) => {
            let expanded = quote! {
                #[derive(
                    Debug,
                    Clone,
                    PartialEq,
                    ::saa_schema::serde::Serialize,
                    ::saa_schema::serde::Deserialize,
                    ::saa_schema::schemars::JsonSchema
                )]
                #[serde( #(#serde_args),* )]
                #[schemars(crate = "::saa_schema::schemars")]
                #[allow(clippy::derive_partial_eq_without_eq)]
                #input
            };
            expanded.into()
        }
        syn::Data::Enum(_) => {
            let expanded = quote! {
                #[derive(
                    Debug,
                    Clone,
                    PartialEq,
                    ::saa_schema::serde::Serialize,
                    ::saa_schema::serde::Deserialize,
                    ::saa_schema::schemars::JsonSchema
                )]
                #[serde( #(#serde_args,)* rename_all = "snake_case")]
                #[schemars(crate = "::saa_schema::schemars")]
                #[allow(clippy::derive_partial_eq_without_eq)]
                #input
            };
            expanded.into()
        }
        syn::Data::Union(_) => panic!("unions are not supported"),
    }
}


fn strum_enum(input: &DeriveInput, attr_args: &[NestedMeta]) -> proc_macro2::TokenStream {
    let ident = &input.ident;

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


    quote! {
        #[derive(
            Debug,
            Clone,
            PartialEq,
            ::saa_schema::strum_macros::Display,
            ::saa_schema::strum_macros::EnumDiscriminants,
            ::saa_schema::strum_macros::VariantNames,
            ::saa_schema::serde::Serialize,
            ::saa_schema::serde::Deserialize,
            ::saa_schema::schemars::JsonSchema,
        )]
        #[strum_discriminants(
            #maybe_name
            derive(
                ::saa_schema::serde::Serialize,
                ::saa_schema::serde::Deserialize,
                ::saa_schema::schemars::JsonSchema,
                ::saa_schema::strum_macros::Display,
                ::saa_schema::strum_macros::EnumString,
                ::saa_schema::strum_macros::VariantArray,
                ::saa_schema::strum_macros::AsRefStr
            ),
            serde(deny_unknown_fields, rename_all = "snake_case", crate = "::saa_schema::serde"),
            strum(serialize_all = "snake_case", crate = "::saa_schema::strum"),
            schemars(crate = "::saa_schema::schemars")
        )]
        #[strum(serialize_all = "snake_case", crate = "::saa_schema::strum")]
        #[serde(deny_unknown_fields, crate = "::saa_schema::serde")]
        #[schemars(crate = "::saa_schema::schemars")]
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


#[proc_macro_attribute]
pub fn saa_str_struct(
    _attr: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let expanded : DeriveInput = match input.data {
        syn::Data::Struct(_) => parse_quote! {
            #[derive(
                Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default
                ::saa_schema::schemars::JsonSchema
            )]
            #[serde(deny_unknown_fields, crate = "::saa_schema::serde")]
            #[schemars(crate = "::saa_schema::schemars")]
            #input 
        },
        syn::Data::Enum(_) => panic!("enums are not supported"),
        syn::Data::Union(_) => panic!("unions are not supported"),
    };

    let stream = expanded.into_token_stream();

    proc_macro::TokenStream::from(stream)
}